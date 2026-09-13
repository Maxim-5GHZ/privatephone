// Push-to-talk full-mesh radio (walkie-talkie). Every member holds a peer
// connection to every other member; only the active speaker sends audio
// (replaceTrack on sendrecv transceivers, so no renegotiation is needed).
// Signaling rides the signed WS relay (`to` may be a single callsign or an
// array), with SDP/ICE and the SFrame group key sealed in an E2EE envelope.
// Media flows P2P between members and is wrapped with SFrame when the browser
// exposes RTCRtpScriptTransform; otherwise the UI is told it is DTLS-only.
// Sessions are ephemeral — nothing is journaled server-side.

import { Envelope } from '../crypto/e2ee'
import { signPacket, SignedPacket } from '../crypto/signing'
import { mkRecipients, openSignal, sealSignal, type SignalPayload } from '../crypto/signal'
import {
  makeSFrameKey,
  sframeFromShare,
  sframeShare,
  sframeSupported,
  type SFrameKey,
  type SFrameShare,
} from '../media/sframe'
import { IceCandidate } from '../types'

export interface PttHandlers {
  send: (p: SignedPacket) => void
  callsign: string
  myPub: () => string
  peerPub: (callsign: string) => string | null
  onSession: (members: string[]) => void
  onTalking: (from: string | null) => void
  onError: (message: string) => void
  /** media-layer security: true when SFrame is actually applied */
  onLink: (secure: boolean) => void
}

interface PttWire {
  n?: string
  to?: string | string[]
  talks?: string
  enc?: Envelope
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
  private groupKey: SFrameKey | null = null
  private secure = false

  constructor(handlers: PttHandlers) {
    this.handlers = handlers
    this.me = handlers.callsign
    this.secure = sframeSupported()
    this.handlers.onLink(this.secure)
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

  // start (creator): derive the group key, share it once and negotiate with
  // every member that has an exchangeable public key.
  async start(targets: string[]): Promise<void> {
    if (this.active) this.closeAll()
    this.sn = Math.random().toString(36).slice(2)
    this.members = Array.from(new Set([this.me, ...targets]))
    this.groupKey = makeSFrameKey()
    this.handlers.onSession(this.members)
    const others = this.offerCandidates()
    if (others.length < this.otherMembers.length) {
      const missing = this.otherMembers.filter((m) => !this.handlers.peerPub(m))
      this.handlers.onError(`Нет ключа: ${missing.join(', ')} — без E2EE-рации`)
    }
    const env = await this.seal(others, { sframe: sframeShare(this.groupKey) })
    await this.signed('ptt_start', { n: this.sn, to: this.addr(others), enc: env })
    for (const m of others) {
      if (this.me < m) await this.offerTo(m)
    }
  }

  // join (invited): a ptt_start frame arrived from the creator with the key.
  join(creator: string, sn: string, to: string[], share: SFrameShare): void {
    if (this.active && this.sn !== sn) this.closeAll()
    this.sn = sn
    this.members = Array.from(new Set([creator, ...to]))
    this.groupKey = sframeFromShare(share, false)
    this.handlers.onSession(this.members)
    for (const m of this.offerCandidates()) {
      if (this.me < m) void this.offerTo(m)
    }
  }

  get active(): boolean {
    return this.sn !== ''
  }

  // setTalking keys/releases the mic on the shared group key. Audio flows to
  // all peers; a talking indicator is spread to the group for mute/unmute.
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
        await this.signed('ptt_talking', { n: this.sn, to: this.addr(this.otherMembers), talks: this.me })
        this.handlers.onTalking(this.me)
      } catch (e) {
        this.handlers.onError(`Микрофон недоступен: ${e instanceof Error ? e.message : String(e)}`)
      }
    } else {
      for (const pc of this.peers.values()) pc.getSenders()[0]?.replaceTrack(null)
      void this.signed('ptt_talking', { n: this.sn, to: this.addr(this.otherMembers), talks: '' })
      this.handlers.onTalking(null)
    }
  }

  end(): void {
    void this.signed('ptt_end', { n: this.sn, to: this.addr(this.otherMembers) })
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
    this.groupKey = null
    this.handlers.onSession([])
    this.handlers.onTalking(null)
  }

  // relayed signaling comes in as the original signed frame. Only the routing
  // fields (n/to/talks) are visible to the mesh node; sdp/candidate live in
  // the `enc` envelope.
  onPeerFrame(kind: string, sender: string, data: Record<string, unknown>): void {
    if (sender === this.me) return
    switch (kind) {
      case 'ptt_start': {
        const sn = String(data.n ?? '')
        if (!sn) return
        void this.handleStart(sender, sn, data)
        break
      }
      case 'ptt_offer':
        void this.open(data, sender).then((p) => {
          if (p?.sdp) void this.onOffer(sender, p.sdp)
        })
        break
      case 'ptt_answer':
        void this.open(data, sender).then((p) => {
          if (p?.sdp) void this.onAnswer(sender, p.sdp)
        })
        break
      case 'ptt_ice':
        void this.open(data, sender).then((p) => {
          if (p?.candidate) this.onIce(sender, p.candidate as IceCandidate)
        })
        break
      case 'ptt_end':
        this.closeAll()
        break
      case 'ptt_talking':
        this.setRemoteTalking(String(data.talks ?? ''))
        break
    }
  }

  private async handleStart(creator: string, sn: string, data: Record<string, unknown>): Promise<void> {
    const to = (Array.isArray(data.to) ? data.to : [data.to]).map(String)
    const pub = this.handlers.peerPub(creator)
    const env = data.enc as Envelope | undefined
    if (!pub || !env) return
    const payload = await openSignal(pub, env)
    if (!payload?.sframe) return
    this.join(creator, sn, to, payload.sframe)
  }

  private async offerTo(peer: string): Promise<void> {
    if (!this.handlers.peerPub(peer)) return
    const pc = this.ensurePC(peer)
    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    const sdp = { type: (offer.type ?? 'offer') as RTCSdpType, sdp: offer.sdp ?? '' }
    const env = await this.seal([peer], { sdp })
    await this.signed('ptt_offer', { n: this.sn, to: peer, enc: env })
  }

  private async onOffer(from: string, sdp: { type: string; sdp: string }): Promise<void> {
    const pc = this.ensurePC(from)
    await pc.setRemoteDescription({ type: sdp.type as RTCSdpType, sdp: sdp.sdp })
    this.flushIce(from)
    const answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    const ansSdp = { type: (answer.type ?? 'answer') as RTCSdpType, sdp: answer.sdp ?? '' }
    const env = await this.seal([from], { sdp: ansSdp })
    await this.signed('ptt_answer', { n: this.sn, to: from, enc: env })
  }

  private async onAnswer(from: string, sdp: { type: string; sdp: string }): Promise<void> {
    const pc = this.peers.get(from)
    if (!pc) return
    await pc.setRemoteDescription({ type: sdp.type as RTCSdpType, sdp: sdp.sdp })
    this.flushIce(from)
  }

  private onIce(from: string, candidate: IceCandidate): void {
    const pc = this.peers.get(from)
    if (!pc) return
    const init = candidate as RTCIceCandidateInit
    if (pc.remoteDescription) void pc.addIceCandidate(init).catch(() => {})
    else this.pendingIce.set(from, [...(this.pendingIce.get(from) ?? []), init])
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
    const tr = pc.addTransceiver('audio', { direction: 'sendrecv' })
    this.attachMediaTransform(tr.sender)
    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return
      void this.seal([peer], { candidate: ev.candidate.toJSON() }).then((env) =>
        void this.signed('ptt_ice', { n: this.sn, to: peer, enc: env }),
      )
    }
    pc.ontrack = (ev) => {
      const el = this.ensureAudio(peer)
      if (this.secure) this.attachReceiverTransform(ev.transceiver.receiver)
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

  private attachMediaTransform(sender: RTCRtpSender): void {
    if (!this.secure) return
    this.transformFor(sender, 'encrypt')
  }

  private attachReceiverTransform(receiver: RTCRtpReceiver): void {
    this.transformFor(receiver, 'decrypt')
  }

  private transformFor(kind: RTCRtpSender | RTCRtpReceiver, side: 'encrypt' | 'decrypt'): void {
    const key = this.groupKey
    if (!key) return
    try {
      const g = globalThis as { RTCRtpScriptTransform?: new (w: Worker, o: unknown) => RTCRtpScriptTransform }
      if (!g.RTCRtpScriptTransform) {
        this.secure = false
        this.handlers.onLink(false)
        return
      }
      const keyCopy = key.key.slice()
      const worker = new Worker(new URL('../media/sframe.worker.ts', import.meta.url), { type: 'module' })
      const options =
        side === 'encrypt'
          ? { key: keyCopy.buffer, outKeyId: key.outKeyId }
          : { key: keyCopy.buffer, inKeyId: key.inKeyId }
      kind.transform = new g.RTCRtpScriptTransform(worker, options)
    } catch {
      this.secure = false
      this.handlers.onLink(false)
    }
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

  private offerCandidates(): string[] {
    return this.otherMembers.filter((m) => this.handlers.peerPub(m) !== null)
  }

  private recipientsFor(targets: string[]) {
    return mkRecipients(this.me, (cs) => (cs === this.me ? this.handlers.myPub() : this.handlers.peerPub(cs)), targets)
  }

  private seal(targets: string[], payload: SignalPayload): Promise<Envelope> {
    return sealSignal(this.recipientsFor(targets), payload)
  }

  private async open(data: Record<string, unknown>, sender: string): Promise<SignalPayload | null> {
    const pub = this.handlers.peerPub(sender)
    const env = data.enc as Envelope | undefined
    if (!pub || !env) return null
    return openSignal(pub, env)
  }

  private async signed(kind: string, data: PttWire): Promise<void> {
    try {
      const p = await signPacket(kind, data)
      this.handlers.send(p)
    } catch (e) {
      this.handlers.onError(`Ошибка подписи: ${e instanceof Error ? e.message : String(e)}`)
    }
  }
}