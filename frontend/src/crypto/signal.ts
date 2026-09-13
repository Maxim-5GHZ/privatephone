// Protected WebRTC signaling: SDP and ICE payloads are sealed with the same
// E2EE envelope as content so a mesh node sees only the routing fields
// (to/n/talks) and never the session description, candidates, or the SFrame
// group key. The SFrame key for the media layer rides in the first signal of
// the session (call_invite / ptt_start).

import { decrypt, encrypt, getEcdhKey, type Envelope } from './e2ee'
import { type SFrameShare } from '../media/sframe'
import { type IceCandidate, type SdpData } from '../types'

export interface SignalPayload {
  sdp?: SdpData
  candidate?: RTCIceCandidateInit
  /** media-layer group key, present exactly once per session */
  sframe?: SFrameShare
}

export interface SignalRecipient {
  callsign: string
  pubPEM: string
}

// mkRecipients builds the encryption recipient set (sender + every target)
// from the available public-key roster, skipping unseen keys.
export function mkRecipients(
  me: string,
  pubOf: (callsign: string) => string | null,
  targets: string[],
): SignalRecipient[] {
  const set = new Map<string, string>()
  for (const cs of [me, ...targets]) {
    const pub = pubOf(cs)
    if (pub) set.set(cs, pub)
  }
  return Array.from(set, ([callsign, pubPEM]) => ({ callsign, pubPEM }))
}

// sealSignal wraps the payload into an E2EE envelope addressed to recipients.
export async function sealSignal(recipients: SignalRecipient[], payload: SignalPayload): Promise<Envelope> {
  if (recipients.length === 0) throw new Error('Нечем зашифровать сигнализацию: нет ключей получателей')
  return encrypt(recipients, JSON.stringify(payload))
}

// openSignal unwraps a signal envelope for the given sender's public key.
// Returns null when the caller is not a recipient or the cargo is malformed.
export async function openSignal(senderPubPEM: string, env: Envelope): Promise<SignalPayload | null> {
  const my = getEcdhKey()
  if (!my || !env) return null
  const plain = await decrypt(my, senderPubPEM, env)
  if (plain === null) return null
  try {
    const payload = JSON.parse(plain) as SignalPayload
    if (!payload || (!payload.sdp && !payload.candidate && !payload.sframe)) return null
    return payload
  } catch {
    return null
  }
}

// isEncSignal tells whether a signaling frame carries protected cargo.
export function isEncSignal(data: Record<string, unknown> | undefined): boolean {
  return !!data && typeof data.enc === 'object' && data.enc !== null
}

// SdpData/IceCandidate re-exports so controllers can type signal payloads
// without importing views/types directly.
export type { IceCandidate, SdpData }