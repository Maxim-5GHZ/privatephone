// WebRTC audio call controller (peer-to-peer between browsers, media does not
// flow through the node). Signaling travels as signed packets relayed by the
// server (`to` field drives routing). Requires a secure context (https/wss).

import { signPacket, SignedPacket } from '../crypto/signing'
import { CallState, IceCandidate, SdpData } from '../types'

export interface CallHandlers {
  send: (p: SignedPacket) => void
  onState: (state: CallState) => void
  /** remote media is available to attach/play */
  onRemote: (stream: MediaStream | null) => void
  /** incoming call is ringing; needs accept() or reject() */
  onIncoming: (peer: string) => void
  onError: (message: string) => void
}

const RING_PATTERN = [0.28, 0.12, 0.28, 0.12, 0.28, 0.4]
const ANSWER_TIMEOUT = 45_000

export class CallController {
  private handlers: CallHandlers
  private pc: RTCPeerConnection | null = null
  private local: MediaStream | null = null
  private peer: string | null = null
  private pendingOffer: RTCSessionDescriptionInit | null = null
  private state: CallState = 'idle'
  private ringing: AudioContext | null = null
  private ringTimer: number | null = null
  private answerTimer: number | null = null

  constructor(handlers: CallHandlers) {
    this.handlers = handlers
  }

  private setState(s: CallState) {
    this.state = s
    this.handlers.onState(s)
  }

  get currentPeer(): string | null {
    return this.peer
  }

  get isBusy(): boolean {
    return this.state !== 'idle' && this.state !== 'ended'
  }

  isIncomingFor(peer: string): boolean {
    return this.state === 'ringing' && this.peer === peer
  }

  // start (caller): create local stream + pc, send offer
  async start(peer: string): Promise<void> {
    if (this.isBusy) {
      this.handlers.onError('Уже идёт вызов')
      return
    }
    this.peer = peer
    try {
      this.local = await navigator.mediaDevices.getUserMedia(this.constraints())
      this.pc = this.makePC()
      this.setState('calling')
      const offer = await this.pc.createOffer()
      await this.pc.setLocalDescription(offer)
      await this.sendSignal('call_invite', { to: peer, sdp: this.sdp() })
      this.answerTimer = window.setTimeout(() => this.hangup('Нет ответа'), ANSWER_TIMEOUT)
    } catch (e) {
      this.cleanup()
      this.setState('ended')
      this.handlers.onError(`Не удалось начать вызов: ${this.msg(e)}`)
    }
  }

  // incoming (callee): ring and wait for accept()
  incoming(peer: string, sdp: SdpData): void {
    if (this.isBusy) {
      void this.sendSignal('call_reject', { to: peer, error: 'busy' })
      return
    }
    this.peer = peer
    this.pendingOffer = { type: sdp.type as RTCSdpType, sdp: sdp.sdp }
    this.setState('ringing')
    this.startRing()
    this.handlers.onIncoming(peer)
  }

  // accept (callee): pick answer and exchange it
  async accept(): Promise<void> {
    if (this.state !== 'ringing' || !this.pendingOffer || !this.peer) return
    this.stopRing()
    const peer = this.peer
    try {
      this.local = await navigator.mediaDevices.getUserMedia(this.constraints())
      this.pc = this.makePC()
      await this.pc.setRemoteDescription(this.pendingOffer)
      this.pendingOffer = null
      this.setState('connecting')
      const answer = await this.pc.createAnswer()
      await this.pc.setLocalDescription(answer)
      await this.sendSignal('call_accept', { to: peer, sdp: this.sdp() })
    } catch (e) {
      this.hangup()
      this.handlers.onError(`Не удалось ответить: ${this.msg(e)}`)
    }
  }

  reject(): void {
    if (!this.peer) return
    const peer = this.peer
    this.stopRing()
    void this.sendSignal('call_reject', { to: peer })
    this.cleanup()
    this.setState('ended')
  }

  hangup(reason?: string): void {
    if (this.peer && (this.state === 'calling' || this.state === 'connecting' || this.state === 'in-call' || this.state === 'ringing')) {
      void this.sendSignal('call_bye', { to: this.peer })
    }
    this.cleanup()
    this.setState('ended')
    if (reason) this.handlers.onError(reason)
  }

  // relayed events from the server (already verified inbound)
  onPeerFrame(kind: string, sender: string, data: Record<string, unknown>): void {
    switch (kind) {
      case 'call_accept':
        if (this.state === 'calling' && this.peer === sender) {
          this.setState('connecting')
          void this.pc?.setRemoteDescription({ type: 'answer', sdp: (data.sdp as SdpData).sdp })
          if (this.answerTimer) window.clearTimeout(this.answerTimer)
        }
        break
      case 'call_reject':
        this.cleanup()
        this.setState('ended')
        this.handlers.onError(`${sender} отклонил(а) вызов`)
        break
      case 'call_bye':
        this.hangup('Вызов завершён')
        break
      case 'ice':
        if ((this.state === 'calling' || this.state === 'connecting' || this.state === 'in-call') && this.peer === sender) {
          void this.pc?.addIceCandidate((data.candidate as IceCandidate) as RTCIceCandidateInit | null).catch(() => {})
        }
        break
    }
  }

  attachRemote(stream: MediaStream | null): void {
    this.handlers.onRemote(stream)
  }

  private makePC(): RTCPeerConnection {
    const pc = new RTCPeerConnection({ iceServers: [] }) // same-LAN: host candidates only
    pc.onicecandidate = (ev) => {
      if (ev.candidate && this.peer) {
        void this.sendSignal('ice', { to: this.peer, candidate: ev.candidate.toJSON() })
      }
    }
    pc.ontrack = (ev) => {
      if (this.state !== 'in-call') this.setState('in-call')
      this.handlers.onRemote(ev.streams[0] ?? new MediaStream([ev.track]))
    }
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        this.hangup('Соединение потеряно')
      }
    }
    if (this.local) for (const track of this.local.getTracks()) pc.addTrack(track, this.local)
    return pc
  }

  private constraints(): MediaStreamConstraints {
    return {
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: false,
    }
  }

  private sdp(): SdpData {
    return { type: this.pc!.localDescription!.type, sdp: this.pc!.localDescription!.sdp }
  }

  private async sendSignal(kind: string, data: Record<string, unknown>): Promise<void> {
    try {
      const p = await signPacket(kind, data)
      this.handlers.send(p)
    } catch (e) {
      this.handlers.onError(`Ошибка подписи: ${this.msg(e)}`)
    }
  }

  private cleanup(): void {
    if (this.answerTimer) window.clearTimeout(this.answerTimer)
    this.answerTimer = null
    this.stopRing()
    this.pendingOffer = null
    this.local?.getTracks().forEach((t) => t.stop())
    this.local = null
    this.pc?.close()
    this.pc = null
    this.peer = null
  }

  private startRing(): void {
    try {
      const ac = new AudioContext()
      const now = ac.currentTime
      let t = now
      for (const d of RING_PATTERN) {
        if (d > 0) {
          const osc = ac.createOscillator()
          const gain = ac.createGain()
          osc.type = 'sine'
          osc.frequency.value = 620
          gain.gain.setValueAtTime(0.12, t)
          gain.gain.setValueAtTime(0, t + d)
          osc.connect(gain).connect(ac.destination)
          osc.start(t)
          osc.stop(t + d)
        }
        t += d
      }
      this.ringing = ac
      this.ringTimer = window.setTimeout(() => this.hangup('Нет ответа'), ANSWER_TIMEOUT)
    } catch {
      /* ringer is best-effort */
    }
  }

  private stopRing(): void {
    if (this.ringTimer) window.clearTimeout(this.ringTimer)
    this.ringTimer = null
    void this.ringing?.close().catch(() => {})
    this.ringing = null
  }

  private msg(e: unknown): string {
    return e instanceof Error ? e.message : String(e)
  }
}