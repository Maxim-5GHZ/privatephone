// Push-to-talk full-mesh radio (walkie-talkie). Every member holds a peer
// connection to every other member; only the active speaker sends audio
// (replaceTrack on sendrecv transceivers, so no renegotiation is needed).
// Signaling rides the signed WS relay (`to` may be a single callsign or an
// array). Sessions are ephemeral — nothing is journaled server-side.

import { signPacket, SignedPacket } from '../crypto/signing'

export interface PttHandlers {
  send: (p: SignedPacket) => void
  callsign: string
  onSession: (members: string[]) => void
  onTalking: (from: string | null) => void
  onError: (message: string) => void
}

interface PttSignal {
  n?: string
  to?: string | string[]
  sdp?: { type: string; sdp: string }
  candidate?: RTCIceCandidateInit
  talks?: string
}

export class PttController {
  private handlers: PttHandlers
  private me: string
  private sn = ''
  private members: string[] = []
  private peers = new Map<string, RTCPeerConnection>()
  private els = new Map<string, HTMLAudioElement>()
  private pendingIce = new Map<string, RTCIceCandidateInit[]>()
  private localTrack: MediaStreamTrack | null = null
  private container: HTMLDivElement

  constructor(handlers: PttHandlers) {
    this.handlers = handlers
    this.me = handlers.callsign
    this.container = document.createElement('div')
    this.container.id = 'ptt-audio'
    this.container.style.display = 'none'
    document.body.appendChild(this.container)
  }

  private get otherMembers(): string[] {
    return this.members.filter((m) => m !== this.me)
  }

  private addr(t: string[]): string | string[] {
    return t.length === 1 ? t[0] : t
  }

  // start (creator): derive the group and negotiate with every member.
  async start(targets: string[]): Promise<void> {
    if (this.active) this.closeAll()
    this.sn = Math.random().toString(36).slice(2)
    this.members = Array.from(new Set([this.me, ...targets]))
    this.handlers.onSession(this.members)
    for (const m of this.otherMembers) {
      if (this.me < m) await this.offerTo(m)
    }
  }

  // join (invited): a ptt_start frame arrived from the creator.
  join(creator: string, sn: string, to: string[]): void {
    if (this.active && this.sn !== sn) this.closeAll()
    this.sn = sn
    this.members = Array.from(new Set([creator, ...to]))
    this.handlers.onSession(this.members)
    for (const m of this.otherMembers) {
      if (this.me < m) void this.offerTo(m)
    }
  }

  get active(): boolean {
    return this.sn !== ''
  }

  // setTalking keys/releases the mic. Audio flows to all peers; a talking
  // indicator is spread to the group so listeners mute/unmute.
  async setTalking(on: boolean): Promise<void> {
    if (on) {
      try {
        if (!this.localTrack) {
          const s = await navigator.mediaDevices.getUserMedia({
            audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
            video: false,
          })
          this.localTrack = s.getAudioTracks()[0]
        }
        for (const pc of this.peers.values()) pc.getSenders()[0]?.replaceTrack(this.localTrack)
        await this.signal('ptt_talking', { n: this.sn, to: this.addr(this.otherMembers), talks: this.me })
        this.handlers.onTalking(this.me)
      } catch (e) {
        this.handlers.onError(`Микрофон недоступен: ${e instanceof Error ? e.message : String(e)}`)
      }
    } else {
      for (const pc of this.peers.values()) pc.getSenders()[0]?.replaceTrack(null)
      void this.signal('ptt_talking', { n: this.sn, to: this.addr(this.otherMembers), talks: '' })
      this.handlers.onTalking(null)
    }
  }

  end(): void {
    void this.signal('ptt_end', { n: this.sn, to: this.addr(this.otherMembers) })
    this.closeAll()
  }

  closeAll(): void {
    for (const pc of this.peers.values()) pc.close()
    this.peers.clear()
    for (const el of this.els.values()) {
      el.srcObject = null
      el.remove()
    }
    this.els.clear()
    this.pendingIce.clear()
    if (this.localTrack) {
      this.localTrack.stop()
      this.localTrack = null
    }
    this.sn = ''
    this.members = []
    this.handlers.onSession([])
    this.handlers.onTalking(null)
  }

  // relayed signaling comes in as the original signed frame
  onPeerFrame(kind: string, sender: string, data: PttSignal): void {
    if (sender === this.me) return
    switch (kind) {
      case 'ptt_start':
        if (data.to) {
          const to = Array.isArray(data.to) ? data.to : [data.to]
          this.join(sender, data.n ?? '', to)
        }
        break
      case 'ptt_offer':
        if (data.sdp) void this.onOffer(sender, data.n ?? '', data.sdp)
        break
      case 'ptt_answer':
        if (data.sdp) void this.onAnswer(sender, data.n ?? '', data.sdp)
        break
      case 'ptt_ice':
        if (data.candidate) this.onIce(sender, data.n ?? '', data.candidate)
        break
      case 'ptt_end':
        this.closeAll()
        break
      case 'ptt_talking':
        this.setRemoteTalking(data.talks ?? '')
        break
    }
  }

  private async offerTo(peer: string): Promise<void> {
    const pc = this.ensurePC(peer)
    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    const sdp = { type: (offer.type ?? 'offer') as RTCSdpType, sdp: offer.sdp ?? '' }
    await this.signal('ptt_offer', { n: this.sn, to: peer, sdp })
  }

  private async onOffer(from: string, sn: string, sdp: { type: string; sdp: string }): Promise<void> {
    if (sn !== this.sn) return
    const pc = this.ensurePC(from)
    await pc.setRemoteDescription({ type: sdp.type as RTCSdpType, sdp: sdp.sdp })
    this.flushIce(from)
    const answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    const ansSdp = { type: (answer.type ?? 'answer') as RTCSdpType, sdp: answer.sdp ?? '' }
    await this.signal('ptt_answer', { n: this.sn, to: from, sdp: ansSdp })
  }

  private async onAnswer(from: string, sn: string, sdp: { type: string; sdp: string }): Promise<void> {
    if (sn !== this.sn) return
    const pc = this.peers.get(from)
    if (!pc) return
    await pc.setRemoteDescription({ type: sdp.type as RTCSdpType, sdp: sdp.sdp })
    this.flushIce(from)
  }

  private onIce(from: string, sn: string, candidate: RTCIceCandidateInit): void {
    if (sn !== this.sn) return
    const pc = this.peers.get(from)
    if (!pc) return
    if (pc.remoteDescription) void pc.addIceCandidate(candidate).catch(() => {})
    else this.pendingIce.set(from, [...(this.pendingIce.get(from) ?? []), candidate])
  }

  private flushIce(from: string): void {
    const pend = this.pendingIce.get(from)
    if (pend) {
      const pc = this.peers.get(from)
      for (const c of pend) void pc?.addIceCandidate(c).catch(() => {})
      this.pendingIce.delete(from)
    }
  }

  private setRemoteTalking(talks: string): void {
    for (const [peer, el] of this.els) {
      el.volume = talks && peer === talks ? 1 : 0
    }
    this.handlers.onTalking(talks || null)
  }

  private ensurePC(peer: string): RTCPeerConnection {
    let pc = this.peers.get(peer)
    if (pc) return pc
    pc = new RTCPeerConnection({ iceServers: [] })
    pc.addTransceiver('audio', { direction: 'sendrecv' })
    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return
      void this.signal('ptt_ice', { n: this.sn, to: peer, candidate: ev.candidate.toJSON() })
    }
    pc.ontrack = (ev) => {
      const el = this.ensureAudio(peer)
      el.srcObject = ev.streams[0] ?? new MediaStream([ev.track])
      void el.play().catch(() => {})
    }
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        this.drop(peer)
      }
    }
    this.peers.set(peer, pc)
    return pc
  }

  private ensureAudio(peer: string): HTMLAudioElement {
    let el = this.els.get(peer)
    if (!el) {
      el = document.createElement('audio')
      el.autoplay = true
      this.container.appendChild(el)
      this.els.set(peer, el)
    }
    return el
  }

  private drop(peer: string): void {
    const pc = this.peers.get(peer)
    if (pc) {
      pc.close()
      this.peers.delete(peer)
    }
    const el = this.els.get(peer)
    if (el) {
      el.srcObject = null
      el.remove()
      this.els.delete(peer)
    }
    this.handlers.onSession(this.members.filter((m) => m === this.me || this.peers.has(m)))
  }

  private async signal(kind: string, data: PttSignal): Promise<void> {
    try {
      const p = await signPacket(kind, data)
      this.handlers.send(p)
    } catch (e) {
      this.handlers.onError(`Ошибка подписи: ${e instanceof Error ? e.message : String(e)}`)
    }
  }
}