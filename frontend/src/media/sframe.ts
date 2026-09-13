// SFrame-style audio codec for WebRTC media. Audio on this mesh is always P2P
// (DTLS-SRTP), so media does not traverse the node — SFrame adds an end-to-end
// layer independent of the transport: without the group SFrame key a mesh node
// that ever relays media, or a compromised endpoint, can neither decrypt nor
// inject continuous audio.
//
// Frame format (SFrame-like, v1):
//   [0x80|keyId (7 bits)] [counter varint (7-bit groups, byte 0 high bit)] [AES-256-GCM body]
// A fresh per-frame key is derived from the group base key via HKDF with the
// (keyId, counter) as salt, so a leaked key never serves two frames.

const SF_INFO = 'pp-sframe/v1'
const SF_IV_BYTES = 12
const SF_KEY_BYTES = 32
const REORDER_LIMIT = 100

export interface SFrameShare {
  /** base64 32-byte group key */
  key: string
  /** keyId used when sending (each direction has its own epoch) */
  outKeyId: number
  /** keyId the remote peer uses to send */
  inKeyId: number
}

export interface SFrameKey {
  key: Uint8Array
  outKeyId: number
  inKeyId: number
}

// makeSFrameKey generates a fresh per-session group key for both directions.
export function makeSFrameKey(): SFrameKey {
  const key = new Uint8Array(SF_KEY_BYTES)
  crypto.getRandomValues(key)
  return { key, outKeyId: 1, inKeyId: 2 }
}

export function sframeShare(k: SFrameKey): SFrameShare {
  return { key: b64(k.key), outKeyId: k.outKeyId, inKeyId: k.inKeyId }
}

// sframeFromShare adopts a shared group key. In 1:1 sessions the callee takes
// the creator's share mirrored (the callee sends on the creator's "in" keyId
// and listens on the creator's "out" keyId), so each direction lives in its
// own epoch. In a PTT group every member keeps the creator's layout and sends
// on the same keyId (mirror=false).
export function sframeFromShare(s: SFrameShare, mirror: boolean): SFrameKey {
  const key = unB64(s.key)
  if (key.length !== SF_KEY_BYTES) throw new Error('bad SFrame key')
  return mirror
    ? { key, outKeyId: s.inKeyId, inKeyId: s.outKeyId }
    : { key, outKeyId: s.outKeyId, inKeyId: s.inKeyId }
}

// sframeSupported reports whether this browser can actually transform encoded
// media (RTCRtpScriptTransform in a Worker). Without it we do not fake E2EE —
// media stays DTLS-protected and the UI says so.
export function sframeSupported(): boolean {
  const g = globalThis as { RTCRtpScriptTransform?: unknown; Worker?: unknown }
  return typeof g.RTCRtpScriptTransform === 'function' && typeof g.Worker === 'function'
}

// encodeVarint writes the counter as a 7-bit-group varint, MSB=continuation.
export function encodeVarint(n: number): Uint8Array {
  if (n < 0 || n > 0xffffffff) throw new Error('counter out of range')
  const out = [n & 0x7f]
  n >>>= 7
  while (n > 0) {
    out.unshift((n & 0x7f) | 0x80)
    n >>>= 7
  }
  return Uint8Array.from(out)
}

export function decodeVarint(b: Uint8Array, off: number): { value: number; next: number } | null {
  let value = 0
  let i = off
  let groups = 0
  while (i < b.length) {
    const byte = b[i++]
    const payload = byte & 0x7f
    // big-endian base-128: most significant group comes first
    value = value * 128 + payload
    if (value > 0xffffffff || ++groups > 5) return null
    if ((byte & 0x80) === 0) return { value, next: i }
  }
  return null
}

// buildSFrameHeader serializes the SFrame-like header.
export function buildSFrameHeader(keyId: number, counter: number): Uint8Array {
  if (keyId < 0 || keyId > 0x7f) throw new Error('keyId out of range')
  const c = encodeVarint(counter)
  const h = new Uint8Array(1 + c.length)
  h[0] = 0x80 | keyId
  h.set(c, 1)
  return h
}

// parseSFrameHeader reads back {keyId, counter} and the body offset.
export function parseSFrameHeader(b: Uint8Array): { keyId: number; counter: number; next: number } | null {
  if (b.length < 2) return null
  if ((b[0] & 0x80) === 0) return null // marker bit must be set (v1)
  const keyId = b[0] & 0x7f
  const v = decodeVarint(b, 1)
  if (!v || v.next > b.length) return null
  return { keyId, counter: v.value, next: v.next }
}

// deriveSFrameMaterial produces the per-frame AES-256 key and GCM nonce from
// the group base key and the (keyId, counter) epoch.
export async function deriveSFrameMaterial(
  base: Uint8Array,
  keyId: number,
  counter: number,
): Promise<{ key: ArrayBuffer; iv: Uint8Array }> {
  if (base.length !== SF_KEY_BYTES) throw new Error('SFrame base key must be 32 bytes')
  const salt = new Uint8Array(1 + 4)
  salt[0] = keyId
  const dv = new DataView(salt.buffer)
  dv.setUint32(1, counter >>> 0, false)
  const hkdf = await crypto.subtle.importKey('raw', base as BufferSource, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode(SF_INFO) },
    hkdf,
    (SF_KEY_BYTES + SF_IV_BYTES) * 8,
  )
  const iv = new Uint8Array(bits, SF_KEY_BYTES, SF_IV_BYTES)
  return { key: bits.slice(0, SF_KEY_BYTES), iv }
}

// Codec encrypts on the sender side and decrypts on the receiver side with
// replay protection. A single group key drives both directions through the
// distinct keyIds.
export class SFrameCodec {
  private base: Uint8Array
  private last = new Map<number, number>()

  constructor(base: Uint8Array) {
    if (base.length !== SF_KEY_BYTES) throw new Error('SFrame base key must be 32 bytes')
    this.base = base
  }

  // encrypt returns the SFrame frame for one encoded audio packet.
  async encrypt(pt: Uint8Array, keyId: number, counter: number): Promise<Uint8Array> {
    const { key, iv } = await deriveSFrameMaterial(this.base, keyId, counter)
    const raw = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt'])
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, raw, pt as BufferSource),
    )
    const h = buildSFrameHeader(keyId, counter)
    const frame = new Uint8Array(h.length + ct.length)
    frame.set(h, 0)
    frame.set(ct, h.length)
    return frame
  }

  // decrypt validates the frame, rejects replays and returns the body
  // {pt, keyId, counter} or null on failure.
  async decrypt(frame: Uint8Array, allowKeyIds: number[]): Promise<{ pt: Uint8Array; keyId: number; counter: number } | null> {
    const hd = parseSFrameHeader(frame)
    if (!hd) return null
    if (!allowKeyIds.includes(hd.keyId)) return null
    const last = this.last.get(hd.keyId) ?? -1
    if (hd.counter < last - REORDER_LIMIT) return null
    if (hd.counter > last) this.last.set(hd.keyId, hd.counter)
    const { key, iv } = await deriveSFrameMaterial(this.base, hd.keyId, hd.counter)
    const raw = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt'])
    const body = frame.subarray(hd.next)
    if (body.length < 16) return null
    try {
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, raw, body as BufferSource))
      return { pt, keyId: hd.keyId, counter: hd.counter }
    } catch {
      return null
    }
  }
}

function b64(u: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i])
  return btoa(bin)
}

function unB64(s: string): Uint8Array {
  const bin = atob(s)
  const u = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i)
  return u
}