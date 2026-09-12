import { describe, expect, it } from 'vitest'
import {
  bootE2EE,
  clearE2ee,
  decrypt,
  encrypt,
  fingerprint,
  getEcdhKey,
  isE2eeArmed,
  looksLikeEnvelope,
  parseEnvelope,
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

describe('e2ee round trip', () => {
  it('sender and addressed recipients can decrypt, strangers cannot', async () => {
    const alice = await keyPair()
    const bob = await keyPair()
    const carol = await keyPair()
    const alicePub = await pubPEM(alice.publicKey)
    const bobPub = await pubPEM(bob.publicKey)

    const env = await encrypt(
      alice.privateKey,
      [
        { callsign: 'bob', pubPEM: bobPub },
        { callsign: 'alice', pubPEM: alicePub },
      ],
      'секретная метка',
    )
    expect(env.v).toBe(1)
    expect(env.alg).toBe('A256GCM')
    expect(env.k.length).toBe(2)

    expect(await decrypt(bob.privateKey, alicePub, env)).toBe('секретная метка')
    expect(await decrypt(alice.privateKey, alicePub, env)).toBe('секретная метка')
    expect(await decrypt(carol.privateKey, alicePub, env)).toBeNull()
  })

  it('tampered ciphertext must not decrypt', async () => {
    const alice = await keyPair()
    const bob = await keyPair()
    const alicePub = await pubPEM(alice.publicKey)
    const env = await encrypt(alice.privateKey, [{ callsign: 'bob', pubPEM: await pubPEM(bob.publicKey) }], 'секрет')
    const tampered = { ...env, c: env.c.slice(0, -2) + (env.c.endsWith('AA') ? 'BB' : 'AA') }
    expect(await decrypt(bob.privateKey, alicePub, tampered)).toBeNull()
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
    const alice = await keyPair()
    const bob = await keyPair()
    const env = await encrypt(alice.privateKey, [{ callsign: 'bob', pubPEM: await pubPEM(bob.publicKey) }], 'x')
    const json = JSON.stringify(env)
    expect(looksLikeEnvelope(json)).toBe(true)
    expect(parseEnvelope(json)).not.toBeNull()
    expect(looksLikeEnvelope('обычный текст')).toBe(false)
    expect(looksLikeEnvelope('{"v":1}')).toBe(false)
    expect(parseEnvelope('балласт')).toBeNull()
  })
})