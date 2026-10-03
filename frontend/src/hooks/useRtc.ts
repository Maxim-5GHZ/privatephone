import { useCallback, useEffect, useRef, useState, type Dispatch, type RefObject, type SetStateAction } from 'react'
import { WSHandle } from '../api/client'
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

  const contRef = useRef<CallController | null>(null)
  const pttRef = useRef<PttController | null>(null)
  const onErrorRef = useRef(onError)
  useEffect(() => {
    onErrorRef.current = onError
  }, [onError])

  useEffect(() => {
    if (!callsign) return
    const cont = new CallController({
      me: callsign,
      send: (p) => wsRef.current?.send(p),
      onState: (state: CallState) => setCall((prev) => ({ ...prev, state })),
      onRemote: (stream) => setRemote(stream),
      onIncoming: (peer) => setCall((prev) => ({ ...prev, incoming: true, peer })),
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
        if (!members.length) setPttTalking(false)
      },
      onTalking: (from) => setPttTalker(from),
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
    if (kind.startsWith('ptt_')) pttRef.current?.onPeerFrame(kind, sender, data)
    else contRef.current?.onPeerFrame(kind, sender, data)
  }, [])

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
      void contRef.current.start(target)
    }
  }, [])

  const acceptCall = useCallback(() => {
    setCall((prev) => ({ ...prev, incoming: false }))
    void contRef.current?.accept()
  }, [])

  const rejectCall = useCallback(() => {
    contRef.current?.reject()
    setCall((prev) => ({ ...prev, incoming: false }))
  }, [])

  const hangupCall = useCallback(() => {
    contRef.current?.hangup()
    setCall((prev) => ({ ...prev, incoming: false, error: null }))
    setRemote(null)
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