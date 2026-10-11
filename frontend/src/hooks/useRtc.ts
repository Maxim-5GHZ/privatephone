import { useCallback, useEffect, useRef, useState, type Dispatch, type RefObject, type SetStateAction } from 'react'
import { WSHandle } from '../api/client'
import { appendCallLog, CallLogEntry, clearCallLog, loadCallLog, pushTalker, TalkMark } from '../call/log'
import { CallController } from '../call/webRTC'
import { PttController } from '../ptt/ptt'
import { CallState } from '../types'
import { CallUi } from '../views/CallOverlay'

export type SignalFn = (kind: string, sender: string, data: Record<string, unknown>) => void

const IDLE_CALL: CallUi = { state: 'idle', peer: null, incoming: false, error: null }

export interface RtcApi {
  call: CallUi
  callSecure: boolean
  remote: MediaStream | null
  pttOpen: boolean
  pttSecure: boolean
  pttSession: string[] | null
  pttTalker: string | null
  pttTalking: boolean
  pttStreams: Map<string, MediaStream>
  /** recent PTT talkers, newest last (local UI queue, not server state) */
  pttRecent: TalkMark[]
  /** local call history (server relay is ephemeral, see call/log.ts) */
  callLog: CallLogEntry[]
  clearHistory: () => void
  setPttOpen: Dispatch<SetStateAction<boolean>>
  startPtt: (targets: string[]) => void
  keyPtt: (on: boolean) => void
  endPtt: () => void
  startCall: (target: string) => void
  acceptCall: () => void
  rejectCall: () => void
  hangupCall: () => void
  handleSignal: SignalFn
  reset: () => void
}

interface RtcOptions {
  callsign: string | null
  wsRef: RefObject<WSHandle | null>
  pubsRef: RefObject<Map<string, string>>
  onError: (msg: string) => void
}

// useRtc owns the WebRTC call + PTT controllers and all their UI state.
// Controllers attach to the WS relay via wsRef and read recipient public keys
// from pubsRef, both owned by the caller (useMesh keeps them fresh).
export function useRtc({ callsign, wsRef, pubsRef, onError }: RtcOptions): RtcApi {
  const [call, setCall] = useState<CallUi>(IDLE_CALL)
  const [callSecure, setCallSecure] = useState(false)
  const [remote, setRemote] = useState<MediaStream | null>(null)
  const [pttOpen, setPttOpen] = useState(false)
  const [pttSecure, setPttSecure] = useState(false)
  const [pttSession, setPttSession] = useState<string[] | null>(null)
  const [pttTalker, setPttTalker] = useState<string | null>(null)
  const [pttTalking, setPttTalking] = useState(false)
  const [pttStreams, setPttStreams] = useState<Map<string, MediaStream>>(new Map())
  const [pttRecent, setPttRecent] = useState<TalkMark[]>([])
  const [callLog, setCallLog] = useState<CallLogEntry[]>([])

  const contRef = useRef<CallController | null>(null)
  const pttRef = useRef<PttController | null>(null)
  const onErrorRef = useRef(onError)
  const meRef = useRef(callsign)
  meRef.current = callsign
  const callRef = useRef(call)
  callRef.current = call
  useEffect(() => {
    onErrorRef.current = onError
  }, [onError])

  // Load per-callsign history on login; reset clears it from the screen.
  useEffect(() => {
    setCallLog(callsign ? loadCallLog(callsign) : [])
    setPttRecent([])
  }, [callsign])

  const log = useCallback((entry: CallLogEntry) => {
    const me = meRef.current
    if (!me) return
    setCallLog(appendCallLog(me, entry))
  }, [])

  useEffect(() => {
    if (!callsign) return
    const cont = new CallController({
      me: callsign,
      send: (p) => wsRef.current?.send(p),
      onState: (state: CallState) => setCall((prev) => ({ ...prev, state })),
      onRemote: (stream) => setRemote(stream),
      onIncoming: (peer) => {
        setCall((prev) => ({ ...prev, incoming: true, peer }))
        const me = meRef.current
        if (me) setCallLog(appendCallLog(me, { peer, dir: 'in', result: 'ringing', at: Date.now() }))
      },
      onError: (msg) => onErrorRef.current(msg),
      onLink: (secure) => setCallSecure(secure),
      myPub: () => pubsRef.current.get(callsign) ?? '',
      peerPub: (cs) => pubsRef.current.get(cs) ?? null,
    })
    const ptt = new PttController({
      send: (p) => wsRef.current?.send(p),
      callsign,
      onSession: (members) => {
        setPttSession(members.length ? members : null)
        if (!members.length) {
          setPttTalking(false)
          setPttRecent([])
        }
      },
      onTalking: (from) => {
        setPttTalker(from)
        if (from) setPttRecent((prev) => pushTalker(prev, from))
      },
      onStream: (peer, stream) => {
        setPttStreams((prev) => {
          const next = new Map(prev)
          if (stream) next.set(peer, stream)
          else next.delete(peer)
          return next
        })
      },
      onError: (msg) => onErrorRef.current(msg),
      onLink: (secure) => setPttSecure(secure),
      myPub: () => pubsRef.current.get(callsign) ?? '',
      peerPub: (cs) => pubsRef.current.get(cs) ?? null,
    })
    contRef.current = cont
    pttRef.current = ptt
    return () => {
      // Tear down controllers on logout/unmount so media streams, timers and
      // peer connections are never leaked into the next session.
      cont.hangup()
      contRef.current = null
      ptt.closeAll()
      pttRef.current = null
    }
  }, [callsign, wsRef, pubsRef])

  const handleSignal = useCallback<SignalFn>((kind, sender, data) => {
    // Server-side call_error (offline peer) is consumed for history here;
    // the user-facing notice stays in useMesh.
    if (kind === 'call_error') {
      const to = typeof data?.to === 'string' ? (data.to as string) : ''
      if (to) log({ peer: to, dir: 'out', result: 'offline', at: Date.now() })
      return
    }
    // Caller hung up while we were ringing → missed incoming.
    if (kind === 'call_bye') {
      const cur = callRef.current
      if (cur.incoming && cur.peer && (!sender || sender === cur.peer)) {
        log({ peer: cur.peer, dir: 'in', result: 'missed', at: Date.now() })
      }
    }
    if (kind.startsWith('ptt_')) pttRef.current?.onPeerFrame(kind, sender, data)
    else contRef.current?.onPeerFrame(kind, sender, data)
  }, [log])

  const startPtt = useCallback((targets: string[]) => {
    setPttOpen(true)
    void pttRef.current?.start(targets)
  }, [])

  const keyPtt = useCallback((on: boolean) => {
    setPttTalking(on)
    void pttRef.current?.setTalking(on)
  }, [])

  const endPtt = useCallback(() => {
    pttRef.current?.end()
  }, [])

  const startCall = useCallback((target: string) => {
    if (contRef.current) {
      setCall({ state: 'calling', peer: target, incoming: false, error: null })
      log({ peer: target, dir: 'out', result: 'calling', at: Date.now() })
      void contRef.current.start(target)
    }
  }, [log])

  const acceptCall = useCallback(() => {
    setCall((prev) => {
      if (prev.peer) log({ peer: prev.peer, dir: 'in', result: 'accepted', at: Date.now() })
      return { ...prev, incoming: false }
    })
    void contRef.current?.accept()
  }, [log])

  const rejectCall = useCallback(() => {
    setCall((prev) => {
      if (prev.peer) log({ peer: prev.peer, dir: 'in', result: 'rejected', at: Date.now() })
      return { ...prev, incoming: false }
    })
    contRef.current?.reject()
  }, [log])

  const hangupCall = useCallback(() => {
    setCall((prev) => {
      if (prev.peer && (prev.state === 'in-call' || prev.state === 'connecting' || prev.state === 'calling')) {
        log({ peer: prev.peer, dir: prev.incoming ? 'in' : 'out', result: 'ended', at: Date.now() })
      }
      return { ...prev, incoming: false, error: null }
    })
    contRef.current?.hangup()
    setRemote(null)
  }, [log])

  const clearHistory = useCallback(() => {
    const me = meRef.current
    if (me) clearCallLog(me)
    setCallLog([])
  }, [])

  const reset = useCallback(() => {
    contRef.current?.hangup()
    contRef.current = null
    pttRef.current?.closeAll()
    pttRef.current = null
    setRemote(null)
    setCall(IDLE_CALL)
    setCallSecure(false)
    setPttOpen(false)
    setPttSecure(false)
    setPttSession(null)
    setPttTalker(null)
    setPttTalking(false)
    setPttStreams(new Map())
    setPttRecent([])
    setCallLog([])
  }, [])

  return {
    call,
    callSecure,
    remote,
    pttOpen,
    pttSecure,
    pttSession,
    pttTalker,
    pttTalking,
    pttStreams,
    pttRecent,
    callLog,
    clearHistory,
    setPttOpen,
    startPtt,
    keyPtt,
    endPtt,
    startCall,
    acceptCall,
    rejectCall,
    hangupCall,
    handleSignal,
    reset,
  }
}