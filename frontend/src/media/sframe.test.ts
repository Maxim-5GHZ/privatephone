import { describe, expect, it } from 'vitest'
import {
  buildSFrameHeader,
  decodeVarint,
  deriveSFrameMaterial,
  encodeVarint,
  makeSFrameKey,
  parseSFrameHeader,
  SFrameCodec,
  sframeFromShare,
  sframeShare,
} from './sframe'

function randKey(): Uint8Array {
  const k = new Uint8Array(32)
  crypto.getRandomValues(k)
  return k
}

describe('sframe varint', () => {
  it('round-trips counters (incl. multi-byte and boundary values)', () => {
    for (const n of [0, 1, 127, 128, 129, 16383, 16384, 123456, 0xffffffff]) {
      const enc = encodeVarint(n)
      const dec = decodeVarint(enc, 0)
      expect(dec).not.toBeNull()
      expect(dec!.value).toBe(n)
      expect(dec!.next).toBe(enc.length)
    }
  })

  it('rejects out-of-range counters and overflows past 32 bits', () => {
    expect(() => encodeVarint(-1)).toThrow()
    expect(() => encodeVarint(0x1_0000_0000)).toThrow()
    expect(decodeVarint(Uint8Array.from([0x81, 0x80, 0x80, 0x80, 0x80, 0x00]), 0)).toBeNull()
    expect(decodeVarint(Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), 0)).toBeNull()
  })
})

describe('sframe header', () => {
  it('round-trips header fields', () => {
    for (const [keyId, counter] of [[0, 0], [1, 5], [42, 70000], [127, 0xffffffff]]) {
      const h = buildSFrameHeader(keyId, counter)
      expect(h[0] & 0x80).toBe(0x80)
      const p = parseSFrameHeader(h)
      expect(p).not.toBeNull()
      expect(p!.keyId).toBe(keyId)
      expect(p!.counter).toBe(counter)
      expect(p!.next).toBe(h.length)
    }
  })

  it('rejects frames without the marker bit and truncated bytes', () => {
    expect(parseSFrameHeader(Uint8Array.from([0x01, 0x00]))).toBeNull()
    expect(parseSFrameHeader(Uint8Array.from([0x82, 0x00]))).not.toBeNull()
    expect(parseSFrameHeader(Uint8Array.from([0x81]))).toBeNull()
  })
})

describe('SFrameCodec', () => {
  it('encrypts and decrypts audio frames round-trip', async () => {
    const base = randKey()
    const codec = new SFrameCodec(base)
    const pt = new Uint8Array(400)
    crypto.getRandomValues(pt)
    const frame = await codec.encrypt(pt, 1, 7)
    const out = await codec.decrypt(frame, [1])
    expect(out).not.toBeNull()
    expect(out!.counter).toBe(7)
    expect(out!.keyId).toBe(1)
    expect(Buffer.from(out!.pt).equals(Buffer.from(pt))).toBe(true)
  })

  it('per-frame key derivation is unique across (keyId, counter) epochs', async () => {
    const base = randKey()
    const a = await deriveSFrameMaterial(base, 1, 1)
    const b = await deriveSFrameMaterial(base, 1, 2)
    const c = await deriveSFrameMaterial(base, 2, 1)
    expect(Buffer.from(a.key as ArrayBuffer).toString('hex')).not.toBe(Buffer.from(b.key).toString('hex'))
    expect(Buffer.from(a.key as ArrayBuffer).toString('hex')).not.toBe(Buffer.from(c.key as ArrayBuffer).toString('hex'))
    expect(Buffer.from(a.iv).toString('hex')).not.toBe(Buffer.from(b.iv).toString('hex'))
  })

  it('rejects tampered ciphertext (GCM auth)', async () => {
    const codec = new SFrameCodec(randKey())
    const frame = await codec.encrypt(new TextEncoder().encode('voice'), 1, 1)
    frame[frame.length - 1] ^= 0xff
    expect(await codec.decrypt(frame, [1])).toBeNull()
  })

  it('rejects frames on a different keyId epoch', async () => {
    const codec = new SFrameCodec(randKey())
    const frame = await codec.encrypt(new TextEncoder().encode('voice'), 2, 1)
    expect(await codec.decrypt(frame, [1])).toBeNull()
  })

  it('rejects replays far behind the running counter (reorder window)', async () => {
    const codec = new SFrameCodec(randKey())
    const frame = await codec.encrypt(new TextEncoder().encode('voice'), 1, 500)
    expect(await codec.decrypt(frame, [1])).not.toBeNull()
    const stale = await codec.encrypt(new TextEncoder().encode('voice'), 1, 300)
    expect(await codec.decrypt(stale, [1])).toBeNull()
  })

  it('encrypts with a wrong key length', () => {
    expect(() => new SFrameCodec(new Uint8Array(16))).toThrow()
  })
})

describe('group key sharing', () => {
  it('share round-trips and 1:1 mirror swaps the keyIds (per-direction epochs)', () => {
    const k = makeSFrameKey()
    expect(k.outKeyId).toBe(1)
    expect(k.inKeyId).toBe(2)
    const share = sframeShare(k)
    const group = sframeFromShare(share, false)
    expect(group.outKeyId).toBe(1)
    expect(group.inKeyId).toBe(2)
    const callee = sframeFromShare(share, true)
    expect(callee.outKeyId).toBe(2)
    expect(callee.inKeyId).toBe(1)
    expect(Buffer.from(group.key).equals(Buffer.from(callee.key))).toBe(true)
  })

  it('mirrored callee key decrypts caller frames and vice versa', async () => {
    const caller = makeSFrameKey()
    const callee = sframeFromShare(sframeShare(caller), true)
    // caller -> callee: caller sends on its out (1); callee listens on its in (1)
    const fwd = await new SFrameCodec(caller.key).encrypt(new TextEncoder().encode('hi'), caller.outKeyId, 3)
    const calleeOut = await new SFrameCodec(callee.key).decrypt(fwd, [callee.inKeyId])
    expect(calleeOut).not.toBeNull()
    // callee -> caller: callee sends on its out (2); caller listens on its in (2)
    const back = await new SFrameCodec(callee.key).encrypt(new TextEncoder().encode('yo'), callee.outKeyId, 0)
    const callerOut = await new SFrameCodec(caller.key).decrypt(back, [caller.inKeyId])
    expect(callerOut).not.toBeNull()
  })
})