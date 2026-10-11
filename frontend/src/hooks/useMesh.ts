import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import {
  apiGet,
  apiPost,
  connectWS,
  createChat as apiCreateChat,
  deleteChat as apiDeleteChat,
  fetchChats,
  revokeSubscriber,
  updateChat as apiUpdateChat,
  WSHandle,
} from '../api/client'
import { encId, recipientList } from '../crypto/content'
import { encrypt, getEcdhKey, looksLikeEnvelope } from '../crypto/e2ee'
import { logout, signPacket } from '../crypto/signing'
import { clearDecryptCache, DecryptItem, useDecrypted } from '../crypto/useDecrypt'
import { Alert, Chat, MARKER_LABEL, Marker, Message, Packet, Subscriber, Snapshot, WSMsg, Zone } from '../types'
import type { SignalFn } from './useRtc'

const nonce = () => Math.random().toString(36).slice(2)

function upsertMarker(list: Marker[], m: Marker): Marker[] {
  const arr = list ?? []
  if (arr.some((x) => x.sender === m.sender && x.n === m.n && m.n !== '')) {
    return arr.map((x) => (x.sender === m.sender && x.n === m.n ? m : x))
  }
  return [...arr, m]
}

function removeMarker(list: Marker[], sender: string, n: string): Marker[] {
  return (list ?? []).filter((x) => !(x.sender === sender && x.n === n))
}

function upsertMessage(list: Message[], m: Message): Message[] {
  const arr = list ?? []
  if (arr.some((x) => x.sender === m.sender && x.n === m.n && m.n !== '')) return arr
  return [...arr, m]
}

function upsertAlert(list: Alert[], a: Alert): Alert[] {
  const arr = list ?? []
  if (arr.some((x) => x.sender === a.sender && x.n === a.n && a.n !== '')) {
    return arr.map((x) => (x.sender === a.sender && x.n === a.n ? a : x))
  }
  return [...arr, a]
}

function removeAlert(list: Alert[], sender: string, n: string): Alert[] {
  return (list ?? []).filter((x) => !(x.sender === sender && x.n === n))
}

function upsertZone(list: Zone[], z: Zone): Zone[] {
  const arr = list ?? []
  if (arr.some((x) => x.sender === z.sender && x.n === z.n && z.n !== '')) {
    return arr.map((x) => (x.sender === z.sender && x.n === z.n ? z : x))
  }
  return [...arr, z]
}

function removeZone(list: Zone[], sender: string, n: string): Zone[] {
  return (list ?? []).filter((x) => !(x.sender === sender && x.n === n))
}

function packetToMarker(p: Packet): Marker | null {
  try {
    const d = JSON.parse(p.payload) as { lat: number; lon: number; type?: string; desc?: string; enc?: unknown }
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
    if (d.enc) {
      return {
        id: -p.ts,
        sender: p.sender,
        recipient: d.recipient ?? '',
        body: JSON.stringify(d.enc),
        n: p.nonce,
        created_at: '',
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

export interface MeshOptions {
  callsign: string | null
  wsRef: RefObject<WSHandle | null>
  pubsRef: RefObject<Map<string, string>>
  signalRef: RefObject<SignalFn>
}

export interface MeshApi {
  markers: Marker[]
  messages: Message[]
  alerts: Alert[]
  zones: Zone[]
  chats: Chat[]
  subscribers: Subscriber[]
  online: string[]
  connected: boolean
  notice: string | null
  toasts: { id: number; text: string }[]
  hydratedMarkers: Marker[]
  hydratedMessages: Message[]
  hydratedZones: Zone[]
  hydratedAlerts: Alert[]
  setNotice: (msg: string | null) => void
  isAdmin: boolean
  sendMessage: (body: string, recipient: string) => void
  sendMarker: (m: { lat: number; lon: number; type: string; desc: string }) => void
  updateMarker: (m: Marker, type: string, desc: string) => void
  deleteMarker: (m: Marker) => void
  sendAlert: (type: string) => void
  ackAlert: (a: Alert) => void
  clearAlert: (a: Alert) => void
  sendZone: (points: [number, number][], name: string, color: string) => void
  updateZone: (z: Zone, name: string, color: string) => void
  deleteZone: (z: Zone) => void
  createSubscriber: (name: string, role: string) => Promise<string | null>
  refreshSubscribers: () => void
  changeSubscriberStatus: (name: string, revoke: boolean) => Promise<void>
  refreshChats: () => void
  createChat: (name: string, members: string[]) => Promise<void>
  updateChat: (id: string, name: string, members: string[]) => Promise<void>
  deleteChat: (id: string) => Promise<void>
  logoutLocal: () => void
}

// useMesh owns the mesh state (markers/messages/alerts/zones/subscribers/
// online), the WS connection, E2EE hydration and every content action.
// Call/PTT signaling frames are routed out through signalRef to the RTC
// controllers owned by useRtc.
export function useMesh({ callsign, wsRef, pubsRef, signalRef }: MeshOptions): MeshApi {
  const [markers, setMarkers] = useState<Marker[]>([])
  const [messages, setMessages] = useState<Message[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [zones, setZones] = useState<Zone[]>([])
  const [chats, setChats] = useState<Chat[]>([])
  const [subscribers, setSubscribers] = useState<Subscriber[]>([])
  const [online, setOnline] = useState<string[]>([])
  const [connected, setConnected] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [toasts, setToasts] = useState<{ id: number; text: string }[]>([])
  const [decryptSession, setDecryptSession] = useState(0)
  const toastId = useRef(0)

  const pubs = useMemo(() => {
    const m = new Map<string, string>()
    for (const s of subscribers) m.set(s.callsign, s.pubkey || '')
    return m
  }, [subscribers])

  useEffect(() => {
    pubsRef.current = pubs
  }, [pubs, pubsRef])

  const decryptItems = useMemo<DecryptItem[]>(() => {
    const items: DecryptItem[] = []
    for (const mk of markers) if (mk.type === 'enc') items.push({ id: encId('mk', mk.sender, mk.desc || ''), sender: mk.sender, text: mk.desc || '', pubPEM: pubs.get(mk.sender) ?? '' })
    for (const a of alerts) if (a.type === 'enc') items.push({ id: encId('al', a.sender, a.text ?? ''), sender: a.sender, text: a.text ?? '', pubPEM: pubs.get(a.sender) ?? '' })
    for (const z of zones) if (z.name === 'enc') items.push({ id: encId('zn', z.sender, z.points || ''), sender: z.sender, text: z.points || '', pubPEM: pubs.get(z.sender) ?? '' })
    for (const m of messages) if (looksLikeEnvelope(m.body)) items.push({ id: encId('ms', m.sender, m.body), sender: m.sender, text: m.body, pubPEM: pubs.get(m.sender) ?? '' })
    return items
  }, [markers, alerts, zones, messages, pubs])
  const decrypted = useDecrypted(decryptItems, decryptSession)

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
      return { ...m, body: decrypted.get(encId('ms', m.sender, m.body)) ?? '[зашифровано]' }
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

  const handleMsg = useCallback(
    (m: WSMsg) => {
      switch (m.kind) {
        case 'snapshot': {
          const s = m.data as Snapshot
          setMarkers(s.markers ?? [])
          setMessages(s.messages ?? [])
          setAlerts(s.alerts ?? [])
          setZones(s.zones ?? [])
          setChats(s.chats ?? [])
          setOnline(s.online ?? [])
          break
        }
        case 'packets': {
          const items = (m.data as { items: Packet[] }).items ?? []
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
                const d = JSON.parse(p.payload) as { n?: string; target?: string; name?: string; color?: string }
                const tn = d.target ?? d.n ?? ''
                setZones((prev) =>
                  prev.map((x) => (x.sender === p.sender && x.n === tn ? { ...x, name: d.name ?? x.name, color: d.color ?? x.color } : x)),
                )
              } catch {
                /* ignore */
              }
            } else if (p.kind === 'zone_delete') {
              setZones((prev) => removeZone(prev, p.sender, p.nonce))
            } else if (p.kind === 'marker_update') {
              try {
                const d = JSON.parse(p.payload) as { n?: string; target?: string; type?: string; desc?: string }
                const tn = d.target ?? d.n ?? ''
                setMarkers((prev) =>
                  prev.map((x) => (x.sender === p.sender && x.n === tn ? { ...x, type: d.type ?? x.type, desc: d.desc ?? x.desc } : x)),
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
          addToast(`Тревога: ${(m.data as Alert).sender}`)
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
        case 'chat_created': {
          const c = m.data as Chat
          setChats((prev) => (prev.some((x) => x.id === c.id) ? prev.map((x) => (x.id === c.id ? c : x)) : [...prev, c]))
          addToast(`Новый чат «${c.name}»`)
          break
        }
        case 'chat_updated': {
          const c = m.data as Chat
          setChats((prev) => prev.map((x) => (x.id === c.id ? c : x)))
          break
        }
        case 'chat_deleted': {
          const d = m.data as { id: string }
          setChats((prev) => prev.filter((x) => x.id !== d.id))
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
          signalRef.current?.(m.kind, (m as { sender?: string }).sender ?? '', m.data as Record<string, unknown>)
          break
        case 'ptt_start':
        case 'ptt_end':
        case 'ptt_talking':
        case 'ptt_offer':
        case 'ptt_answer':
        case 'ptt_ice':
          signalRef.current?.(m.kind, (m as { sender?: string }).sender ?? '', m.data as Record<string, unknown>)
          break
        case 'call_error':
          setNotice(`Не удалось позвонить ${(m.data as { to: string }).to}: ${(m.data as { error?: string }).error ?? 'недоступен'}`)
          break
      }
    },
    [addToast, wsRef, signalRef],
  )

  useEffect(() => {
    if (!callsign) return
    const h = connectWS(handleMsg, (open) => {
      setConnected(open)
      if (open) setNotice(null)
    })
    wsRef.current = h
    apiGet('/api/v1/subscribers', 'list_subscribers')
      .then((d) => {
        setSubscribers((d as { subscribers: Subscriber[] }).subscribers ?? [])
      })
      .catch((e) => {
        // Не глотаем: чаще всего это чужой ключ (другой data-каталог).
        setNotice(
          `Сервер отклонил ключ ${(e as Error).message}. Войдите заново файлом из data-каталога этого узла.`,
        )
      })
    fetchChats()
      .then((c) => setChats((c as Chat[]) ?? []))
      .catch(() => {})
    return () => {
      h.close()
      wsRef.current = null
    }
  }, [callsign, handleMsg, wsRef])

  const sendEnc = async (kind: string, path: string, plaintext: object, recipient = '', outer: Record<string, unknown> = {}) => {
    if (!getEcdhKey()) throw new Error('E2EE-ключ недоступен: печатайте этим же PEM')
    // named chat: encrypt for chat members, store recipient as "chat:<id>"
    let recips = recipientList(recipient)
    if (recipient.startsWith('chat:')) {
      const chatId = recipient.slice(5)
      const chat = chats.find((c) => c.id === chatId)
      if (!chat) throw new Error('Чат не найден (обновите список чатов)')
      recips = [...chat.members]
    }
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
    return apiPost(path, kind, { n: nonce(), recipient, enc: env, ...outer })
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
      // target: plaintext routing to the original nonce — the envelope `n`
      // is always fresh, so the server cannot look the marker up by it.
      const rec = (await sendEnc('marker_update', '/api/v1/markers', { lat: m.lat, lon: m.lon, type, desc }, '', { target: m.n })) as Marker
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
      const rec = (await sendEnc('zone_update', '/api/v1/zones', { points: pts, name, color }, '', { target: z.n })) as Zone
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
      .then((d) => setSubscribers((d as { subscribers: Subscriber[] }).subscribers ?? []))
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

  const logoutLocal = () => {
    logout()
    clearDecryptCache()
    setDecryptSession((s) => s + 1)
    setMarkers([])
    setMessages([])
    setAlerts([])
    setZones([])
    setChats([])
    setSubscribers([])
    setOnline([])
    setNotice(null)
  }

  const refreshChats = () => {
    fetchChats()
      .then((c) => setChats((c as Chat[]) ?? []))
      .catch(() => {})
  }

  const createChat = async (name: string, members: string[]) => {
    try {
      const rec = (await apiCreateChat(name, members)) as Chat
      setChats((prev) => [...prev, rec])
      addToast(`Чат «${rec.name}» создан`)
    } catch (e) {
      setNotice((e as Error).message)
      throw e
    }
  }

  const updateChat = async (id: string, name: string, members: string[]) => {
    try {
      const rec = (await apiUpdateChat(id, name, members)) as Chat
      setChats((prev) => prev.map((x) => (x.id === id ? rec : x)))
      addToast(`Чат «${rec.name}» обновлён`)
    } catch (e) {
      setNotice((e as Error).message)
      throw e
    }
  }

  const deleteChat = async (id: string) => {
    try {
      await apiDeleteChat(id)
      setChats((prev) => prev.filter((x) => x.id !== id))
      addToast('Чат удалён')
    } catch (e) {
      setNotice((e as Error).message)
      throw e
    }
  }

  const isAdmin = !!(subscribers ?? []).find((s) => s.callsign === callsign)?.role.includes('admin')

  return {
    markers,
    messages,
    alerts,
    zones,
    chats,
    subscribers,
    online,
    connected,
    notice,
    toasts,
    hydratedMarkers,
    hydratedMessages,
    hydratedZones,
    hydratedAlerts,
    setNotice,
    isAdmin,
    sendMessage,
    sendMarker,
    updateMarker,
    deleteMarker,
    sendAlert,
    ackAlert,
    clearAlert,
    sendZone,
    updateZone,
    deleteZone,
    createSubscriber,
    refreshSubscribers,
    changeSubscriberStatus,
    refreshChats,
    createChat,
    updateChat,
    deleteChat,
    logoutLocal,
  }
}