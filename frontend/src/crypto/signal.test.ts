import { describe, expect, it } from 'vitest'
import { bootE2EE, clearE2ee, encrypt } from './e2ee'
import { mkRecipients, openSignal, sealSignal } from './signal'

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

function b64b(buf: ArrayBuffer): string {
  return Buffer.from(new Uint8Array(buf)).toString('base64')
}

describe('mkRecipients', () => {
  it('builds sender+target set, skips unknown public keys', () => {
    const pubOf = (cs: string) => (cs === 'me' ? 'ME' : cs === 'bob' ? 'BOB' : null)
    const r = mkRecipients('me', pubOf, ['bob', 'ghost'])
    expect(r.map((x) => x.callsign).sort()).toEqual(['bob', 'me'])
  })
})

describe('sealSignal / openSignal', () => {
  it('sealed SDP opens only for addressed recipients', async () => {
    const bob = await keyPair()
    const carol = await keyPair()
    const bobPub = await pubPEM(bob.publicKey)
    const bobPriv = await privPEM(bob.privateKey)
    const carolPriv = await privPEM(carol.privateKey)
    const payload = { sdp: { type: 'offer', sdp: 'v=0 ...' }, sframe: { key: 'aGVsbG8=', outKeyId: 1, inKeyId: 2 } }

    const env = await sealSignal([{ callsign: 'alice', pubPEM: await pubPEM((await keyPair()).publicKey) }, { callsign: 'bob', pubPEM: bobPub }], payload)
    expect(env.v).toBe(2)

    await bootE2EE(bobPriv)
    const opened = await openSignal(bobPub, env)
    expect(opened).not.toBeNull()
    expect(opened!.sdp?.sdp).toBe('v=0 ...')
    expect(opened!.sframe?.outKeyId).toBe(1)
    expect(opened!.sframe!.key).toBe('aGVsbG8=')
    clearE2ee()

    await bootE2EE(carolPriv)
    expect(await openSignal(bobPub, env)).toBeNull()
    clearE2ee()
  })

  it('sealing without any recipient keys fails loudly', async () => {
    await expect(sealSignal([], { sdp: { type: 'offer', sdp: 'x' } })).rejects.toThrow()
  })

  it('candidate-only and sframe-only payloads parse', async () => {
    const bob = await keyPair()
    const priv = await privPEM(bob.privateKey)
    const pub = await pubPEM(bob.publicKey)
    const cand = await encrypt([{ callsign: 'bob', pubPEM: pub }], JSON.stringify({ candidate: { candidate: 'cand:1', sdpMid: '0', sdpMLineIndex: 0 } }))
    await bootE2EE(priv)
    const out = await openSignal(pub, cand)
    expect(out?.candidate?.candidate).toBe('cand:1')
    expect(out?.candidate?.sdpMLineIndex).toBe(0)
    clearE2ee()
  })

  it('encrypted transport of the envelope is b64 JSON (opaque to the node)', async () => {
    const bob = await keyPair()
    const env = await encrypt([{ callsign: 'bob', pubPEM: await pubPEM(bob.publicKey) }], '{"sdp":{}}')
    expect(typeof b64b(new TextEncoder().encode(JSON.stringify(env)))).toBe('string')
  })
})