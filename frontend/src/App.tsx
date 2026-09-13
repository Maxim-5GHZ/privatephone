import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { apiGet, apiPost, connectWS, revokeSubscriber, WSHandle } from './api/client'
import { CallController } from './call/webRTC'
import { encId, recipientList } from './crypto/content'
import { encrypt, getEcdhKey, looksLikeEnvelope } from './crypto/e2ee'
import { getCallsign, logout, signPacket } from './crypto/signing'
import { DecryptItem, useDecrypted } from './crypto/useDecrypt'
import { PttController } from './ptt/ptt'
import { Alert, CallState, MARKER_LABEL, Marker, Message, Packet, Subscriber, Snapshot, WSMsg, Zone } from './types'
import { AdminView } from './views/AdminView'
import { AlertBanner } from './views/AlertBanner'
import { CallOverlay, CallUi } from './views/CallOverlay'
import { ChatView } from './views/ChatView'
import { Login } from './views/Login'
import { MapView } from './views/MapView'
import { PttPanel } from './views/PttPanel'
import './index.css'

type Tab = 'map' | 'chat' | 'admin'

const nonce = () => Math.random().toString(36).slice(2)

function upsertMarker(list: Marker[], m: Marker): Marker[] {
  if (list.some((x) => x.sender === m.sender && x.n === m.n && m.n !== '')) {
    return list.map((x) => (x.sender === m.sender && x.n === m.n ? m : x))
  }
  return [...list, m]
}

function removeMarker(list: Marker[], sender: string, n: string): Marker[] {
  return list.filter((x) => !(x.sender === sender && x.n === n))
}

function upsertMessage(list: Message[], m: Message): Message[] {
  if (list.some((x) => x.sender === m.sender && x.n === m.n && m.n !== '')) return list
  return [...list, m]
}

function upsertAlert(list: Alert[], a: Alert): Alert[] {
  if (list.some((x) => x.sender === a.sender && x.n === a.n && a.n !== '')) {
    return list.map((x) => (x.sender === a.sender && x.n === a.n ? a : x))
  }
  return [...list, a]
}

function removeAlert(list: Alert[], sender: string, n: string): Alert[] {
  return list.filter((x) => !(x.sender === sender && x.n === n))
}

function upsertZone(list: Zone[], z: Zone): Zone[] {
  if (list.some((x) => x.sender === z.sender && x.n === z.n && z.n !== '')) {
    return list.map((x) => (x.sender === z.sender && x.n === z.n ? z : x))
  }
  return [...list, z]
}

function removeZone(list: Zone[], sender: string, n: string): Zone[] {
  return list.filter((x) => !(x.sender === sender && x.n === n))
}

function packetToMarker(p: Packet): Marker | null {
  try {
    const d = JSON.parse(p.payload) as { lat: number; lon: number; type?: string; desc?: string; enc?: unknown }
    // encrypted markers are carried by the snapshots/list projections
    if (d.enc) return null
    if (typeof d.lat !== 'number' || typeof d.lon !== 'number') return null
    return { id: -p.ts, sender: p.sender, lat: d.lat, lon: d.lon, type: d.type ?? 'other', desc: d.desc ?? '', n: p.nonce, created_at: '' }
  } catch {
    return null
  }
}

function packetToMessage(p: Packet): Message | null {
  try {
    const d = JSON.parse(p.payload) as { body?: string; recipient?: string; enc?: unknown }
    if (typeof d.body === 'string') {
      return { id: -p.ts, sender: p.sender, recipient: d.recipient ?? '', body: d.body, n: p.nonce, created_at: '' }
    }
    // E2EE cargo: body carries only the opaque envelope; the plaintext is
    // recovered off-thread by the hydration layer.
    if (d.enc) {
      return {
        id: -p.ts,
        sender: p.sender,
        recipient: d.recipient ?? '',
        body: JSON.stringify(d.enc),
        n: p.nonce,
        created_at: '',
        encrypted: true,
      }
    }
    return null
  } catch {
    return null
  }
}

function packetToAlert(p: Packet): Alert | null {
  try {
    const d = JSON.parse(p.payload) as { type?: string; text?: string; enc?: unknown }
    if (d.enc) return null
    if (!d.type) return null
    return { id: -p.ts, sender: p.sender, type: d.type, text: d.text ?? '', n: p.nonce, created_at: '' }
  } catch {
    return null
  }
}

function packetToZone(p: Packet): Zone | null {
  try {
    const d = JSON.parse(p.payload) as { name?: string; color?: string; points?: unknown; enc?: unknown }
    if (d.enc) return null
    if (!Array.isArray(d.points)) return null
    return { id: -p.ts, sender: p.sender, name: d.name ?? 'Зона', color: d.color ?? '#ff3b30', points: JSON.stringify(d.points), n: p.nonce, created_at: '' }
  } catch {
    return null
  }
}

export default function App() {
  const [callsign, setCallsign] = useState<string | null>(() => getCallsign())
  const [tab, setTab] = useState<Tab>('map')
  const [markers, setMarkers] = useState<Marker[]>([])
  const [messages, setMessages] = useState<Message[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [zones, setZones] = useState<Zone[]>([])
  const [subscribers, setSubscribers] = useState<Subscriber[]>([])
  const [online, setOnline] = useState<string[]>([])
  const [connected, setConnected] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [toasts, setToasts] = useState<{ id: number; text: string }[]>([])
  const [call, setCall] = useState<CallUi>({ state: 'idle', peer: null, incoming: false, error: null })
  const [callSecure, setCallSecure] = useState(false)
  const [remote, setRemote] = useState<MediaStream | null>(null)
  const [pttOpen, setPttOpen] = useState(false)
  const [pttSecure, setPttSecure] = useState(false)
  const [pttSession, setPttSession] = useState<string[] | null>(null)
  const [pttTalker, setPttTalker] = useState<string | null>(null)
  const [pttTalking, setPttTalking] = useState(false)

  const wsRef = useRef<WSHandle | null>(null)
  const contRef = useRef<CallController | null>(null)
  const pttRef = useRef<PttController | null>(null)
  const toastId = useRef(0)

  const pubs = useMemo(() => {
    const m = new Map<string, string>()
    for (const s of subscribers) m.set(s.callsign, s.pubkey || '')
    return m
  }, [subscribers])

  // Live public-key map for the call/PTT controllers: they are created once
  // per login, but the subscriber roster loads asynchronously afterwards.
  const pubsRef = useRef(new Map<string, string>())
  useEffect(() => {
    pubsRef.current = pubs
  }, [pubs])

  // Collect every opaque E2EE envelope currently in state and decrypt them in
  // the background; leaves are hydrated once, then cached for the session.
  const decryptItems = useMemo<DecryptItem[]>(() => {
    const items: DecryptItem[] = []
    for (const mk of markers) if (mk.type === 'enc') items.push({ id: encId('mk', mk.sender, mk.desc || ''), sender: mk.sender, text: mk.desc || '', pubPEM: pubs.get(mk.sender) ?? '' })
    for (const a of alerts) if (a.type === 'enc') items.push({ id: encId('al', a.sender, a.text ?? ''), sender: a.sender, text: a.text ?? '', pubPEM: pubs.get(a.sender) ?? '' })
    for (const z of zones) if (z.name === 'enc') items.push({ id: encId('zn', z.sender, z.points || ''), sender: z.sender, text: z.points || '', pubPEM: pubs.get(z.sender) ?? '' })
    for (const m of messages) if (looksLikeEnvelope(m.body)) items.push({ id: encId('ms', m.sender, m.body), sender: m.sender, text: m.body, pubPEM: pubs.get(m.sender) ?? '' })
    return items
  }, [markers, alerts, zones, messages, pubs])
  const decrypted = useDecrypted(decryptItems)

  // Hydrated projections: enc rows become their readable equivalents.
  const hydratedMarkers = useMemo(() => {
    const out: Marker[] = []
    for (const mk of markers) {
      if (mk.type !== 'enc') {
        out.push(mk)
        continue
      }
      const plain = decrypted.get(encId('mk', mk.sender, mk.desc || ''))
      if (!plain) continue
      try {
        const d = JSON.parse(plain) as { lat: number; lon: number; type?: string; desc?: string }
        if (typeof d.lat !== 'number' || typeof d.lon !== 'number') continue
        out.push({ ...mk, lat: d.lat, lon: d.lon, type: d.type ?? 'other', desc: d.desc ?? '' })
      } catch {
        /* keep out */
      }
    }
    return out
  }, [markers, decrypted])

  const hydratedMessages = useMemo(() => {
    return messages.map((m) => {
      if (!looksLikeEnvelope(m.body)) return m
      return { ...m, body: decrypted.get(encId('ms', m.sender, m.body)) ?? '[зашифровано]', encrypted: true }
    })
  }, [messages, decrypted])

  const hydratedZones = useMemo(() => {
    const out: Zone[] = []
    for (const z of zones) {
      if (z.name !== 'enc') {
        out.push(z)
        continue
      }
      const plain = decrypted.get(encId('zn', z.sender, z.points || ''))
      if (!plain) {
        out.push(z)
        continue
      }
      try {
        const d = JSON.parse(plain) as { name?: string; color?: string; points?: unknown }
        out.push({ ...z, name: d.name ?? 'Зона', color: d.color ?? '#ff3b30', points: JSON.stringify(Array.isArray(d.points) ? d.points : []) })
      } catch {
        out.push(z)
      }
    }
    return out
  }, [zones, decrypted])

  const hydratedAlerts = useMemo(() => {
    const out: Alert[] = []
    for (const a of alerts) {
      if (a.type !== 'enc') {
        out.push(a)
        continue
      }
      const plain = decrypted.get(encId('al', a.sender, a.text ?? ''))
      if (!plain) {
        out.push(a)
        continue
      }
      try {
        const d = JSON.parse(plain) as { type?: string; text?: string }
        out.push({ ...a, type: d.type ?? 'info', text: d.text ?? '' })
      } catch {
        out.push(a)
      }
    }
    return out
  }, [alerts, decrypted])

  const addToast = useCallback((text: string) => {
    const id = ++toastId.current
    setToasts((prev) => [...prev.slice(-2), { id, text }])
    window.setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 7000)
  }, [])

  const handleMsg = useCallback((m: WSMsg) => {
    switch (m.kind) {
      case 'snapshot': {
        const s = m.data as Snapshot
        setMarkers(s.markers)
        setMessages(s.messages)
        setAlerts(s.alerts ?? [])
        setZones(s.zones ?? [])
        setOnline(s.online ?? [])
        break
      }
      case 'packets': {
        const items = (m.data as { items: Packet[] }).items
        const ids: string[] = []
        let newMarkers: Marker[] = []
        let newMessages: Message[] = []
        let newAlerts: Alert[] = []
        let newZones: Zone[] = []
        for (const p of items) {
          ids.push(p.id)
          if (p.kind === 'marker') {
            const mm = packetToMarker(p)
            if (mm) newMarkers = upsertMarker(newMarkers, mm)
          } else if (p.kind === 'message') {
            const mm = packetToMessage(p)
            if (mm) newMessages = upsertMessage(newMessages, mm)
          } else if (p.kind === 'alert') {
            const aa = packetToAlert(p)
            if (aa) newAlerts = upsertAlert(newAlerts, aa)
          } else if (p.kind === 'alert_clear') {
            try {
              const d = JSON.parse(p.payload) as { author?: string }
              setAlerts((prev) => removeAlert(prev, d.author ?? p.sender, p.nonce))
            } catch {
              /* ignore */
            }
          } else if (p.kind === 'zone') {
            const zz = packetToZone(p)
            if (zz) newZones = upsertZone(newZones, zz)
          } else if (p.kind === 'zone_update') {
            try {
              const d = JSON.parse(p.payload) as { name?: string; color?: string }
              setZones((prev) =>
                prev.map((x) => (x.sender === p.sender && x.n === p.nonce ? { ...x, name: d.name ?? x.name, color: d.color ?? x.color } : x)),
              )
            } catch {
              /* ignore */
            }
          } else if (p.kind === 'zone_delete') {
            setZones((prev) => removeZone(prev, p.sender, p.nonce))
          } else if (p.kind === 'marker_update') {
            try {
              const d = JSON.parse(p.payload) as { n: string; type?: string; desc?: string }
              setMarkers((prev) =>
                prev.map((x) => (x.sender === p.sender && x.n === d.n ? { ...x, type: d.type ?? x.type, desc: d.desc ?? x.desc } : x)),
              )
            } catch {
              /* ignore */
            }
          } else if (p.kind === 'marker_delete') {
            try {
              const d = JSON.parse(p.payload) as { n: string }
              setMarkers((prev) => removeMarker(prev, p.sender, d.n))
            } catch {
              /* ignore */
            }
          }
        }
        if (newMarkers.length) setMarkers((prev) => prev.concat(newMarkers.filter((x) => !prev.some((y) => y.sender === x.sender && y.n === x.n))))
        if (newMessages.length) setMessages((prev) => prev.concat(newMessages.filter((x) => !prev.some((y) => y.sender === x.sender && y.n === x.n))))
        if (newAlerts.length) setAlerts((prev) => prev.concat(newAlerts.filter((x) => !prev.some((y) => y.sender === x.sender && y.n === x.n))))
        if (newZones.length) setZones((prev) => prev.concat(newZones.filter((x) => !prev.some((y) => y.sender === x.sender && y.n === x.n))))
        void signPacket('ack', { ids }).then((p) => wsRef.current?.send(p)).catch(() => {})
        break
      }
      case 'marker': {
        const mk = m.data as Marker
        setMarkers((prev) => upsertMarker(prev, mk))
        addToast(`${mk.sender}: метка «${MARKER_LABEL[mk.type] ?? mk.type}»`)
        break
      }
      case 'marker_updated':
        setMarkers((prev) => upsertMarker(prev, m.data as Marker))
        break
      case 'marker_deleted': {
        const d = m.data as { sender: string; n: string }
        setMarkers((prev) => removeMarker(prev, d.sender, d.n))
        addToast(`${d.sender} убрал(а) метку`)
        break
      }
      case 'message':
        setMessages((prev) => upsertMessage(prev, m.data as Message))
        break
      case 'alert':
        setAlerts((prev) => upsertAlert(prev, m.data as Alert))
        addToast(`Тревога: ${((m.data as Alert).sender)}`)
        break
      case 'alert_acks': {
        const d = m.data as { author: string; n: string; sender: string }
        setAlerts((prev) =>
          prev.map((a) =>
            a.sender === d.author && a.n === d.n ? { ...a, acks: Array.from(new Set([...(a.acks ?? []), d.sender])) } : a,
          ),
        )
        break
      }
      case 'alert_cleared': {
        const d = m.data as { author: string; n: string }
        setAlerts((prev) => removeAlert(prev, d.author, d.n))
        addToast('Тревога снята')
        break
      }
      case 'zone':
        setZones((prev) => upsertZone(prev, m.data as Zone))
        break
      case 'zone_updated':
        setZones((prev) => upsertZone(prev, m.data as Zone))
        break
      case 'zone_deleted': {
        const d = m.data as { sender: string; n: string }
        setZones((prev) => removeZone(prev, d.sender, d.n))
        break
      }
      case 'presence':
        setOnline((m.data as { online: string[] }).online ?? [])
        break
      case 'call_invite':
      case 'call_accept':
      case 'call_reject':
      case 'call_bye':
      case 'ice':
        contRef.current?.onPeerFrame(m.kind, (m as { sender?: string }).sender ?? '', m.data as Record<string, unknown>)
        break
      case 'ptt_start':
      case 'ptt_end':
      case 'ptt_talking':
      case 'ptt_offer':
      case 'ptt_answer':
      case 'ptt_ice':
        pttRef.current?.onPeerFrame(m.kind, (m as { sender?: string }).sender ?? '', m.data as Record<string, unknown>)
        break
      case 'call_error':
        setNotice(`Не удалось позвонить ${(m.data as { to: string }).to}: ${(m.data as { error?: string }).error ?? 'недоступен'}`)
        break
    }
  }, [addToast])

  useEffect(() => {
    if (!callsign) return
    const h = connectWS(handleMsg, (open) => {
      setConnected(open)
      if (open) setNotice(null)
    })
    wsRef.current = h
    apiGet('/api/v1/subscribers', 'list_subscribers')
      .then((d) => setSubscribers((d as { subscribers: Subscriber[] }).subscribers))
      .catch(() => {})
    return () => {
      h.close()
      wsRef.current = null
    }
  }, [callsign, handleMsg])

  useEffect(() => {
    if (!callsign || contRef.current) return
    contRef.current = new CallController({
      me: callsign,
      send: (p) => wsRef.current?.send(p),
      onState: (state: CallState) => setCall((prev) => ({ ...prev, state })),
      onRemote: (stream) => setRemote(stream),
      onIncoming: (peer) => setCall((prev) => ({ ...prev, incoming: true, peer })),
      onError: (msg) => setNotice(msg),
      onLink: (secure) => setCallSecure(secure),
      myPub: () => pubsRef.current.get(callsign) ?? '',
      peerPub: (cs) => pubsRef.current.get(cs) ?? null,
    })
    pttRef.current = new PttController({
      send: (p) => wsRef.current?.send(p),
      callsign,
      onSession: (members) => {
        setPttSession(members.length ? members : null)
        if (!members.length) setPttTalking(false)
      },
      onTalking: (from) => setPttTalker(from),
      onError: (msg) => setNotice(msg),
      onLink: (secure) => setPttSecure(secure),
      myPub: () => pubsRef.current.get(callsign) ?? '',
      peerPub: (cs) => pubsRef.current.get(cs) ?? null,
    })
  }, [callsign])

  // Every content path goes through E2EE: the wire payload carries only an
  // opaque envelope ({enc}) plus the routing fields the server needs.
  const sendEnc = async (kind: string, path: string, plaintext: object, recipient = '') => {
    if (!getEcdhKey()) throw new Error('E2EE-ключ недоступен: печатайте этим же PEM')
    const recips = recipientList(recipient)
    const union = new Map<string, string>()
    for (const s of subscribers) if (!s.revoked && pubs.get(s.callsign)) union.set(s.callsign, pubs.get(s.callsign)!)
    for (const c of recips) {
      const k = pubs.get(c)
      if (k && !union.has(c)) union.set(c, k)
    }
    if (callsign && pubs.get(callsign)) union.set(callsign, pubs.get(callsign)!)
    const members = Array.from(union, ([cs, pubPEM]) => ({ callsign: cs, pubPEM }))
    if (members.length === 0) throw new Error('Нет известных ключей получателей')
    const env = await encrypt(members, JSON.stringify(plaintext))
    return apiPost(path, kind, { n: nonce(), recipient, enc: env })
  }

  const sendMessage = async (body: string, recipient: string) => {
    if (!callsign) return
    try {
      const rec = (await sendEnc('message', '/api/v1/messages', { body }, recipient)) as Message
      setMessages((prev) => upsertMessage(prev, rec))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const sendMarker = async (m: { lat: number; lon: number; type: string; desc: string }) => {
    try {
      const rec = (await sendEnc('marker', '/api/v1/markers', m)) as Marker
      setMarkers((prev) => upsertMarker(prev, rec))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const updateMarker = async (m: Marker, type: string, desc: string) => {
    try {
      const rec = (await sendEnc('marker_update', '/api/v1/markers', { lat: m.lat, lon: m.lon, type, desc })) as Marker
      setMarkers((prev) => upsertMarker(prev, rec))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const deleteMarker = async (m: Marker) => {
    try {
      await apiPost('/api/v1/markers', 'marker_delete', { n: m.n })
      setMarkers((prev) => removeMarker(prev, m.sender, m.n))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const sendAlert = async (type: string) => {
    try {
      const rec = (await sendEnc('alert', '/api/v1/alerts', { type, text: '', lat: 0, lon: 0 })) as Alert
      setAlerts((prev) => upsertAlert(prev, rec))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const ackAlert = async (a: Alert) => {
    try {
      await apiPost('/api/v1/alerts', 'alert_ack', { author: a.sender, n: a.n })
      setAlerts((prev) => prev.map((x) => (x.sender === a.sender && x.n === a.n ? { ...x, acks: Array.from(new Set([...(x.acks ?? []), callsign!])) } : x)))
      addToast('Принято')
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const clearAlert = async (a: Alert) => {
    try {
      await apiPost('/api/v1/alerts', 'alert_clear', { author: a.sender, n: a.n })
      setAlerts((prev) => removeAlert(prev, a.sender, a.n))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const sendZone = async (points: [number, number][], name: string, color: string) => {
    try {
      const rec = (await sendEnc('zone', '/api/v1/zones', { points, name, color })) as Zone
      setZones((prev) => upsertZone(prev, rec))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const updateZone = async (z: Zone, name: string, color: string) => {
    try {
      let pts: [number, number][] = []
      try {
        pts = JSON.parse(z.points) as [number, number][]
      } catch {
        /* keep [] */
      }
      const rec = (await sendEnc('zone_update', '/api/v1/zones', { points: pts, name, color })) as Zone
      setZones((prev) => upsertZone(prev, rec))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const deleteZone = async (z: Zone) => {
    try {
      await apiPost('/api/v1/zones', 'zone_delete', { n: z.n })
      setZones((prev) => removeZone(prev, z.sender, z.n))
    } catch (e) {
      setNotice((e as Error).message)
    }
  }

  const startPtt = (targets: string[]) => {
    setPttOpen(true)
    void pttRef.current?.start(targets)
  }

  const keyPtt = (on: boolean) => {
    setPttTalking(on)
    void pttRef.current?.setTalking(on)
  }

  const endPtt = () => {
    pttRef.current?.end()
  }

  const startCall = (target: string) => {
    if (contRef.current) {
      setCall({ state: 'calling', peer: target, incoming: false, error: null })
      void contRef.current.start(target)
    }
  }

  const acceptCall = () => {
    setCall((prev) => ({ ...prev, incoming: false }))
    void contRef.current?.accept()
  }

  const rejectCall = () => {
    contRef.current?.reject()
    setCall((prev) => ({ ...prev, incoming: false }))
  }

  const hangupCall = () => {
    contRef.current?.hangup()
    setCall((prev) => ({ ...prev, incoming: false, error: null }))
    setRemote(null)
  }

  const createSubscriber = async (name: string, role: string): Promise<string | null> => {
    try {
      const d = (await apiPost('/api/v1/ca/subscribers', 'create_subscriber', { callsign: name, role })) as {
        private_pem: string
      }
      return d.private_pem
    } catch (e) {
      setNotice((e as Error).message)
      return null
    }
  }

  const refreshSubscribers = () => {
    apiGet('/api/v1/subscribers', 'list_subscribers')
      .then((d) => setSubscribers((d as { subscribers: Subscriber[] }).subscribers))
      .catch(() => {})
  }

  const changeSubscriberStatus = async (name: string, revoke: boolean) => {
    try {
      await revokeSubscriber(name, revoke)
      addToast(revoke ? `Доступ «${name}» отозван` : `Доступ «${name}» восстановлен`)
    } catch (e) {
      setNotice((e as Error).message)
      throw e
    }
  }

  const doLogout = () => {
    contRef.current?.hangup()
    contRef.current = null
    pttRef.current?.closeAll()
    pttRef.current = null
    logout()
    setCallsign(null)
    setMarkers([])
    setMessages([])
    setAlerts([])
    setZones([])
    setSubscribers([])
    setOnline([])
    setRemote(null)
    setCall({ state: 'idle', peer: null, incoming: false, error: null })
    setCallSecure(false)
    setPttOpen(false)
    setPttSecure(false)
    setPttSession(null)
    setPttTalker(null)
    setPttTalking(false)
  }

  const isAdmin = !!subscribers.find((s) => s.callsign === callsign)?.role.includes('admin')

  if (!callsign) return <Login onLogin={setCallsign} />

  return (
    <div className="app">
      <header>
        <div className="brand">ПАК АСК</div>
        <nav>
          <button className={tab === 'map' ? 'active' : ''} onClick={() => setTab('map')}>
            Карта
          </button>
          <button className={tab === 'chat' ? 'active' : ''} onClick={() => setTab('chat')}>
            Сообщения
          </button>
          <button className={tab === 'admin' ? 'active' : ''} onClick={() => setTab('admin')}>
            Абоненты
          </button>
          <button className={pttOpen ? 'active' : ''} onClick={() => setPttOpen((v) => !v)}>
            Рация
          </button>
        </nav>
        <div className="status">
          <span className={`dot ${connected ? 'ok' : 'bad'}`} /> {connected ? 'связь' : 'нет канала'}
        </div>
        <div className="who">
          <span className="callsign">{callsign}</span>
          <button className="ghost" onClick={doLogout}>
            Выйти
          </button>
        </div>
      </header>

      {notice && (
        <div className="notice" onClick={() => setNotice(null)}>
          {notice}
        </div>
      )}

      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className="event-toast">
            {t.text}
          </div>
        ))}
      </div>

      <AlertBanner alerts={hydratedAlerts} myCallsign={callsign} isAdmin={isAdmin} onAck={(a) => void ackAlert(a)} onClear={(a) => void clearAlert(a)} />

      {pttOpen && (
        <PttPanel
          online={online}
          myCallsign={callsign}
          session={pttSession}
          talker={pttTalker}
          talkingMe={pttTalking}
          secure={pttSecure}
          onStart={startPtt}
          onKey={keyPtt}
          onEnd={endPtt}
        />
      )}

      {tab === 'map' && (
        <MapView
          markers={hydratedMarkers}
          zones={hydratedZones}
          myCallsign={callsign}
          onSubmit={(m) => void sendMarker(m)}
          onUpdate={(m, type, desc) => void updateMarker(m, type, desc)}
          onDelete={(m) => void deleteMarker(m)}
          onAlert={(t) => void sendAlert(t)}
          onZoneSubmit={(points, name, color) => void sendZone(points, name, color)}
          onZoneUpdate={(z, name, color) => void updateZone(z, name, color)}
          onZoneDelete={(z) => void deleteZone(z)}
        />
      )}
      {tab === 'chat' && (
        <ChatView
          messages={hydratedMessages}
          subscribers={subscribers}
          online={online}
          myCallsign={callsign}
          onSend={(b, r) => void sendMessage(b, r)}
          onCall={startCall}
        />
      )}
      {tab === 'admin' && (
        <AdminView
          subscribers={subscribers}
          onCreate={createSubscriber}
          onRefresh={refreshSubscribers}
          onRevoke={changeSubscriberStatus}
        />
      )}

      <CallOverlay call={call} remote={remote} secure={callSecure} onAccept={acceptCall} onReject={rejectCall} onHangup={hangupCall} />
    </div>
  )
}