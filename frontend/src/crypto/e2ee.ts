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
}

export const E2EE_INFO = 'pp-e2ee/v1'

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

// fingerprint returns a short out-of-band verification anchor for a public key.
export async function fingerprint(pubPEM: string): Promise<string> {
  const der = await crypto.subtle.importKey('spki', pemToDer(pubPEM), { name: 'ECDH', namedCurve: 'P-256' }, true, [])
  const raw = await crypto.subtle.exportKey('raw', der)
  const hashBuf = await crypto.subtle.digest('SHA-256', raw)
  const hash = Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  return hash.toUpperCase().slice(0, 8)
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

async function deriveKek(sharedSecret: ArrayBuffer, salt: Uint8Array): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits'])
  return crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: new TextEncoder().encode(E2EE_INFO) },
    key,
    256,
  )
}

// encrypt builds the envelope for a plaintext payload addressed to the given
// recipients (the sender's own key is always wrapped too, so every client uses
// the same decrypt path).
export async function encrypt(
  myPriv: CryptoKey,
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

  const k: EnvKey[] = []
  for (const r of recipients) {
    const theirPub = await pubkeyToEcdh(r.pubPEM)
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirPub }, myPriv, 256)
    const salt = rand(32)
    const kek = await deriveKek(shared, salt)
    const iv = rand(12)
    const ek = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, await aesKey(kek), msgKey)
    k.push({ to: r.callsign, salt: b64(salt.buffer), iv: b64(iv.buffer), ek: b64(ek) })
  }
  return { v: 1, alg: 'A256GCM', iv: b64(iv0.buffer), c: b64(c), k }
}

// decrypt opens an envelope produced by encrypt when the caller holds one of
// the wrapped recipient keys. Returns the plaintext or null when the caller is
// not a recipient / key mismatch.
export async function decrypt(
  myPriv: CryptoKey,
  senderPubPEM: string,
  env: Envelope,
): Promise<string | null> {
  try {
    const senderPub = await pubkeyToEcdh(senderPubPEM)
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: senderPub }, myPriv, 256)
    for (const entry of env.k) {
      const kek = await deriveKek(shared, b64ToBytes(entry.salt))
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
// envelope (legacy rows store the plaintext directly).
export function looksLikeEnvelope(s: string): boolean {
  if (!s || s[0] !== '{') return false
  try {
    const o = JSON.parse(s)
    return o && o.v === 1 && typeof o.c === 'string' && Array.isArray(o.k)
  } catch {
    return false
  }
}

// parseEnvelope parses a stored envelope, returning null for legacy plaintext.
export function parseEnvelope(s: string): Envelope | null {
  try {
    const o = JSON.parse(s)
    if (o && o.v === 1 && typeof o.c === 'string' && Array.isArray(o.k)) return o as Envelope
  } catch {
    /* not an envelope */
  }
  return null
}