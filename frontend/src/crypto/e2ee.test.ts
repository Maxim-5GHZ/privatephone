import { describe, expect, it } from 'vitest'
import {
  bootE2EE,
  clearE2ee,
  decrypt,
  E2EE_INFO_V1,
  encrypt,
  fingerprint,
  getEcdhKey,
  isE2eeArmed,
  looksLikeEnvelope,
  parseEnvelope,
  pubkeyFromRaw,
  pubkeyToEcdh,
} from './e2ee'

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
}

function b64(buf: ArrayBuffer): string {
  const u = new Uint8Array(buf)
  let bin = ''
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i])
  return btoa(bin)
}

async function pubPEM(k: CryptoKey): Promise<string> {
  const der = await crypto.subtle.exportKey('spki', k)
  return `-----BEGIN PUBLIC KEY-----\n${b64(der)}\n-----END PUBLIC KEY-----`
}

async function privPEM(k: CryptoKey): Promise<string> {
  const der = await crypto.subtle.exportKey('pkcs8', k)
  return `-----BEGIN PRIVATE KEY-----\n${b64(der)}\n-----END PRIVATE KEY-----`
}

// makeV1Envelope reproduces the frozen v1 (static-static ECDH) envelope format,
// used as a legacy fixture to prove new rows still decrypt old stored rows.
async function makeV1Envelope(
  senderPriv: CryptoKey,
  member: { callsign: string; pub: CryptoKey },
): Promise<EnvelopeLike> {
  const msgKey = new Uint8Array(32)
  crypto.getRandomValues(msgKey)
  const iv0 = new Uint8Array(12)
  crypto.getRandomValues(iv0)
  const aes = (raw: BufferSource) => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
  const c = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv0 as BufferSource },
    await aes(msgKey),
    new TextEncoder().encode('legacy v1'),
  )
  const theirPub = await pubkeyToEcdh(await pubPEM(member.pub))
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirPub }, senderPriv, 256)
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits'])
  const salt = new Uint8Array(32)
  crypto.getRandomValues(salt)
  const kek = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode(E2EE_INFO_V1) },
    hkdf,
    256,
  )
  const iv = new Uint8Array(12)
  crypto.getRandomValues(iv)
  const ek = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, await aes(kek), msgKey)
  return {
    v: 1,
    alg: 'A256GCM',
    iv: b64(iv0.buffer),
    c: b64(c),
    k: [{ to: member.callsign, salt: b64(salt.buffer), iv: b64(iv.buffer), ek: b64(ek) }],
  }
}

interface EnvelopeLike {
  v: number
  alg: string
  iv: string
  c: string
  k: { to: string; salt: string; iv: string; ek: string }[]
}

describe('e2ee round trip (v2 ephemeral ECDH)', () => {
  it('sender and addressed recipients can decrypt, strangers cannot', async () => {
    const alice = await keyPair()
    const bob = await keyPair()
    const carol = await keyPair()
    const alicePub = await pubPEM(alice.publicKey)
    const bobPub = await pubPEM(bob.publicKey)

    const env = await encrypt(
      [
        { callsign: 'bob', pubPEM: bobPub },
        { callsign: 'alice', pubPEM: alicePub },
      ],
      'секретная метка',
    )
    expect(env.v).toBe(2)
    expect(env.epub).toBeTruthy()
    expect(env.alg).toBe('A256GCM')
    expect(env.k.length).toBe(2)

    expect(await decrypt(bob.privateKey, alicePub, env)).toBe('секретная метка')
    expect(await decrypt(alice.privateKey, alicePub, env)).toBe('секретная метка')
    expect(await decrypt(carol.privateKey, alicePub, env)).toBeNull()
  })

  it('each envelope uses a fresh ephemeral key (unique ciphertexts/wraps)', async () => {
    const bob = await keyPair()
    const pub = await pubPEM(bob.publicKey)
    const recipients = [{ callsign: 'bob', pubPEM: pub }]
    const e1 = await encrypt(recipients, 'same text')
    const e2 = await encrypt(recipients, 'same text')
    expect(e1.c).not.toBe(e2.c)
    expect(e1.epub).not.toBe(e2.epub)
    expect(e1.k[0].ek).not.toBe(e2.k[0].ek)
  })

  it('tampered ciphertext or tampered epub must not decrypt', async () => {
    const alice = await keyPair()
    const bob = await keyPair()
    const alicePub = await pubPEM(alice.publicKey)
    const env = await encrypt([{ callsign: 'bob', pubPEM: await pubPEM(bob.publicKey) }], 'секрет')
    const tamperedC = { ...env, c: env.c.slice(0, -2) + (env.c.endsWith('AA') ? 'BB' : 'AA') }
    expect(await decrypt(bob.privateKey, alicePub, tamperedC)).toBeNull()
    const tamperedEpub = { ...env, epub: (await pubPEM(alice.publicKey)).slice(0, 16) }
    expect(await decrypt(bob.privateKey, alicePub, tamperedEpub)).toBeNull()
  })

  it('legacy v1 envelopes (static-static) still decrypt', async () => {
    const alice = await keyPair()
    const bob = await keyPair()
    const alicePub = await pubPEM(alice.publicKey)
    const legacy = await makeV1Envelope(alice.privateKey, { callsign: 'bob', pub: bob.publicKey })
    expect(await decrypt(bob.privateKey, alicePub, legacy)).toBe('legacy v1')
    expect(await decrypt(alice.privateKey, alicePub, legacy)).toBeNull()
  })

  it('v2 epub re-import participates in the same ECDH secret', async () => {
    const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
    const raw = await crypto.subtle.exportKey('raw', eph.publicKey)
    const re = await pubkeyFromRaw(b64(raw))
    const carol = await keyPair()
    const viaEph = await crypto.subtle.deriveBits({ name: 'ECDH', public: carol.publicKey }, eph.privateKey, 256)
    const viaRe = await crypto.subtle.deriveBits({ name: 'ECDH', public: re }, carol.privateKey, 256)
    expect(b64(viaEph)).toBe(b64(viaRe))
  })
})

describe('bootE2EE lifecycle', () => {
  it('arms with a PKCS#8 PEM and clears on logout', async () => {
    const alice = await keyPair()
    const pem = await privPEM(alice.privateKey)
    expect(isE2eeArmed()).toBe(false)
    expect(await bootE2EE(pem)).toBe(true)
    expect(isE2eeArmed()).toBe(true)
    expect(getEcdhKey()).not.toBeNull()
    expect(await bootE2EE('-----BEGIN PRIVATE KEY-----\nbogus\n-----END PRIVATE KEY-----')).toBe(false)
    expect(isE2eeArmed()).toBe(false)
    clearE2ee()
    expect(isE2eeArmed()).toBe(false)
  })
})

describe('fingerprint', () => {
  it('is a stable 8-hex anchor', async () => {
    const alice = await keyPair()
    const bob = await keyPair()
    const alicePub = await pubPEM(alice.publicKey)
    const f1 = await fingerprint(alicePub)
    expect(f1).toMatch(/^[0-9A-F]{8}$/)
    expect(await fingerprint(alicePub)).toBe(f1)
    expect(await fingerprint(await pubPEM(bob.publicKey))).not.toBe(f1)
  })
})

describe('envelope detection', () => {
  it('recognises envelopes and rejects legacy/plain text', async () => {
    const bob = await keyPair()
    const env = await encrypt([{ callsign: 'bob', pubPEM: await pubPEM(bob.publicKey) }], 'x')
    const json = JSON.stringify(env)
    expect(looksLikeEnvelope(json)).toBe(true)
    expect(parseEnvelope(json)).not.toBeNull()
    expect(looksLikeEnvelope('обычный текст')).toBe(false)
    expect(looksLikeEnvelope('{"v":1}')).toBe(false)
    expect(parseEnvelope('балласт')).toBeNull()
  })

  it('accepts v1 and v2, rejects unknown versions and v2 without epub', async () => {
    expect(looksLikeEnvelope('{"v":1,"c":"a","k":[]}')).toBe(true)
    expect(looksLikeEnvelope('{"v":2,"epub":"x","c":"a","k":[]}')).toBe(true)
    expect(looksLikeEnvelope('{"v":2,"c":"a","k":[]}')).toBe(false)
    expect(looksLikeEnvelope('{"v":3,"c":"a","k":[]}')).toBe(false)
    expect(parseEnvelope('{"v":2,"epub":"x","c":"a","k":[]}')?.v).toBe(2)
    expect(parseEnvelope('{"v":2,"c":"a","k":[]}')).toBeNull()
  })
})