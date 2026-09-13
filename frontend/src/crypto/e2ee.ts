// End-to-end encryption layer. The operator's P-256 keypair doubles as a
// static ECDH identity: the same PKCS#8 PEM that signs packets also derives
// per-recipient message keys. Public keys are exchanged via the subscriber
// registry (anonymous to the node, which only sees ciphertext).

let ecdhKey: CryptoKey | null = null

export interface EnvKey {
  to: string
  salt: string
  iv: string
  ek: string
}

export interface Envelope {
  v: number
  alg: string
  iv: string
  c: string
  k: EnvKey[]
  // epub (v2+) is the sender's per-envelope ephemeral P-256 public key. The
  // message key wrap is derived from ECDH(ephPriv, recipientStatic) instead of
  // the static-static secret, so future compromise of a static signing key does
  // not unlock past envelopes (forward secrecy).
  epub?: string
}

export const E2EE_INFO_V1 = 'pp-e2ee/v1'
export const E2EE_INFO_V2 = 'pp-e2ee/v2'

export function isE2eeArmed(): boolean {
  return ecdhKey !== null
}

export function getEcdhKey(): CryptoKey | null {
  return ecdhKey
}

// clearE2ee drops the in-memory ECDH twin key (logout).
export function clearE2ee(): void {
  ecdhKey = null
}

// bootE2EE re-imports the same PKCS#8 PEM under the ECDH algorithm so the same
// USB key can be used for signing (ECDSA) and key agreement (ECDH). The key is
// never extractable and never touched localStorage.
export async function bootE2EE(pem: string): Promise<boolean> {
  try {
    ecdhKey = await crypto.subtle.importKey(
      'pkcs8',
      pemToDer(pem),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    )
    return true
  } catch {
    ecdhKey = null
    return false
  }
}

function pemToDer(pem: string): ArrayBuffer {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/[\r\n\s]/g, '')
  const bin = atob(body)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes.buffer as ArrayBuffer
}

export async function pubkeyToEcdh(pubPEM: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'spki',
    pemToDer(pubPEM),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
}

// pubkeyFromRaw re-imports an ephemeral public key carried as raw b64 in v2
// envelopes. WebCrypto's importKey validates that the point lies on the curve.
export async function pubkeyFromRaw(rawB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    b64ToBytes(rawB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
}

// fingerprint returns a short out-of-band verification anchor for a public key.
export async function fingerprint(pubPEM: string): Promise<string> {
  return fingerprintFromSPKI(pemToDer(pubPEM))
}

// fingerprintFromSPKI computes the identity fingerprint from an SPKI DER blob:
// the raw P-256 point is SHA-256-hashed and truncated to 8 hex chars.
export async function fingerprintFromSPKI(spki: ArrayBuffer): Promise<string> {
  const der = await crypto.subtle.importKey('spki', spki, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
  const raw = await crypto.subtle.exportKey('raw', der)
  const hashBuf = await crypto.subtle.digest('SHA-256', raw as BufferSource)
  const hash = Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  return hash.toUpperCase().slice(0, 8)
}

// fingerprintOfPrivate derives the identity fingerprint directly from the
// private PKCS#8 PEM (login preview). The extractable import is discarded
// immediately; nothing is persisted.
export async function fingerprintOfPrivate(pem: string): Promise<string> {
  const priv = await crypto.subtle.importKey('pkcs8', pemToDer(pem), { name: 'ECDH', namedCurve: 'P-256' }, true, [])
  const spki = await crypto.subtle.exportKey('spki', priv)
  return fingerprintFromSPKI(spki)
}

function b64(bytes: ArrayBuffer): string {
  const u = new Uint8Array(bytes)
  let bin = ''
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i])
  return btoa(bin)
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

function rand(n: number): Uint8Array {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

async function deriveKek(sharedSecret: ArrayBuffer, salt: Uint8Array, info: string): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits'])
  return crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode(info) },
    key,
    256,
  )
}

// encrypt builds a v2 envelope (per-envelope ephemeral ECDH) for the given
// plaintext addressed to the given recipients. Each message gets a fresh
// ephemeral keypair; the msg-key is wrapped per recipient under a KEK derived
// from ECDH(ephPriv, recipientStaticPub). Compromising the sender's static key
// later therefore reveals nothing about past envelopes.
export async function encrypt(
  recipients: { callsign: string; pubPEM: string }[],
  plaintext: string,
): Promise<Envelope> {
  const msgKey = rand(32)
  const iv0 = rand(12)
  const c = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv0 as BufferSource },
    await aesKey(msgKey),
    new TextEncoder().encode(plaintext),
  )

  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const epubRaw = await crypto.subtle.exportKey('raw', eph.publicKey)

  const k: EnvKey[] = []
  for (const r of recipients) {
    const theirPub = await pubkeyToEcdh(r.pubPEM)
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirPub }, eph.privateKey, 256)
    const salt = rand(32)
    const kek = await deriveKek(shared, salt, E2EE_INFO_V2)
    const iv = rand(12)
    const ek = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, await aesKey(kek), msgKey)
    k.push({ to: r.callsign, salt: b64(salt.buffer), iv: b64(iv.buffer), ek: b64(ek) })
  }
  return { v: 2, alg: 'A256GCM', epub: b64(epubRaw), iv: b64(iv0.buffer), c: b64(c), k }
}

// decrypt opens an envelope produced by encrypt when the caller holds one of
// the wrapped recipient keys. v2 envelopes use ECDH(myStaticPriv, epub); v1
// (legacy stored rows) falls back to the old static-static derivation. Returns
// the plaintext or null when the caller is not a recipient / key mismatch.
export async function decrypt(
  myPriv: CryptoKey,
  senderPubPEM: string,
  env: Envelope,
): Promise<string | null> {
  try {
    let shared: ArrayBuffer
    let info: string
    if (env.v === 2 && env.epub) {
      const ephPub = await pubkeyFromRaw(env.epub)
      shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: ephPub }, myPriv, 256)
      info = E2EE_INFO_V2
    } else {
      const senderPub = await pubkeyToEcdh(senderPubPEM)
      shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: senderPub }, myPriv, 256)
      info = E2EE_INFO_V1
    }
    for (const entry of env.k) {
      const kek = await deriveKek(shared, b64ToBytes(entry.salt), info)
      let msgKey: ArrayBuffer
      try {
        msgKey = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: b64ToBytes(entry.iv) as BufferSource },
          await aesKey(kek),
          b64ToBytes(entry.ek),
        )
      } catch {
        continue
      }
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(env.iv) as BufferSource },
        await aesKey(msgKey),
        b64ToBytes(env.c),
      )
      return new TextDecoder().decode(plain)
    }
    return null
  } catch {
    return null
  }
}

function aesKey(raw: BufferSource): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

// looksLikeEnvelope guesses whether a stored text field carries an E2EE
// envelope (legacy rows store the plaintext directly). Accepts v1 and v2.
export function looksLikeEnvelope(s: string): boolean {
  if (!s || s[0] !== '{') return false
  try {
    const o = JSON.parse(s)
    return (
      o &&
      (o.v === 1 || o.v === 2) &&
      typeof o.c === 'string' &&
      Array.isArray(o.k) &&
      (o.v === 1 || typeof o.epub === 'string')
    )
  } catch {
    return false
  }
}

// parseEnvelope parses a stored envelope, returning null for legacy plaintext.
export function parseEnvelope(s: string): Envelope | null {
  try {
    const o = JSON.parse(s)
    if (
      o &&
      (o.v === 1 || o.v === 2) &&
      typeof o.c === 'string' &&
      Array.isArray(o.k) &&
      (o.v === 1 || typeof o.epub === 'string')
    ) {
      return o as Envelope
    }
  } catch {
    /* not an envelope */
  }
  return null
}