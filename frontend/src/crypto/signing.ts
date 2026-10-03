// WebCrypto-based ECDSA P-256 signing. The user's private key is imported from
// a PKCS#8 PEM file picked from the USB flash; it lives only in memory and is
// never persisted by the page. The same PEM is also imported as an ECDH key for
// end-to-end encryption (see crypto/e2ee.ts).

import { bootE2EE, clearE2ee, isE2eeArmed } from './e2ee'

let signingKey: CryptoKey | null = null
let callsign: string | null = null

export function isLoggedIn(): boolean {
  return signingKey !== null && callsign !== null
}

export function getCallsign(): (string | null) {
  return callsign
}

export function logout(): void {
  signingKey = null
  callsign = null
  clearE2ee()
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

export async function loginFromPem(pem: string, signCallsign: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'pkcs8',
      pemToDer(pem),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    )
    signingKey = key
    callsign = signCallsign.trim()
    await bootE2EE(pem)
    return true
  } catch {
    signingKey = null
    callsign = null
    return false
  }
}

// e2eeAvailable reports whether the ECDH twin of the signing key was booted.
export function e2eeAvailable(): boolean {
  return isE2eeArmed()
}

function b64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}

function randNonce(): string {
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  return b64(b)
}

// rawToDer converts a WebCrypto ECDSA signature (raw r||s, 64 bytes for
// P-256) to ASN.1-DER, which is what the Go server verifies with
// ecdsa.VerifyASN1. WebCrypto returns IEEE P1363, Go expects DER — sending
// raw bytes is why every packet was rejected with "invalid signature".
export function rawToDer(raw: Uint8Array): Uint8Array {
  const trim = (b: Uint8Array): Uint8Array => {
    let i = 0
    while (i < b.length - 1 && b[i] === 0) i++
    return b.slice(i)
  }
  let r = trim(raw.slice(0, 32))
  let s = trim(raw.slice(32, 64))
  if (r[0] & 0x80) {
    const nr = new Uint8Array(r.length + 1)
    nr[0] = 0
    nr.set(r, 1)
    r = nr
  }
  if (s[0] & 0x80) {
    const ns = new Uint8Array(s.length + 1)
    ns[0] = 0
    ns.set(s, 1)
    s = ns
  }
  const total = 2 + r.length + 2 + s.length
  const out = new Uint8Array(2 + total)
  let o = 0
  out[o++] = 0x30
  out[o++] = total
  out[o++] = 0x02
  out[o++] = r.length
  out.set(r, o)
  o += r.length
  out[o++] = 0x02
  out[o++] = s.length
  out.set(s, o)
  return out
}

export interface SignedPacket {
  headers: Record<string, string>
  body: string
  ts: number
  nonce: string
  signature: string
}

// signPacket builds canonical bytes exactly like the Go server, signs them and
// returns the REST-style envelope (headers + raw JSON body). Pass a string to
// use it verbatim as the raw body (needed for empty GET payloads).
export async function signPacket(kind: string, data: unknown): Promise<SignedPacket> {
  if (!signingKey || !callsign) throw new Error('not logged in')
  const body = typeof data === 'string' ? data : JSON.stringify(data)
  const ts = Math.floor(Date.now() / 1000)
  const nonce = randNonce()
  const canonical = `v=1\nkind=${kind}\nsender=${callsign}\nts=${ts}\nnonce=${nonce}\n${body}`
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingKey,
    new TextEncoder().encode(canonical),
  )
  const raw = new Uint8Array(sigBuf)
  // WebCrypto gives 64-byte P1363; server expects DER (see rawToDer).
  const der = raw.length === 64 ? rawToDer(raw) : raw
  const signature = b64(der)
  return {
    headers: {
      'X-Sender': callsign,
      'X-Kind': kind,
      'X-TS': String(ts),
      'X-Nonce': nonce,
      'X-Signature': signature,
    },
    body,
    ts,
    nonce,
    signature,
  }
}

// buildWSFrame serializes a signed packet as a WebSocket frame whose "data"
// field carries the exact raw bytes that were signed.
export function buildWSFrame(p: SignedPacket): string {
  return (
    `{"sender":${JSON.stringify(p.headers['X-Sender'])},` +
    `"ts":${p.ts},"nonce":${JSON.stringify(p.nonce)},` +
    `"kind":${JSON.stringify(p.headers['X-Kind'])},` +
    `"signature":${JSON.stringify(p.signature)},"data":${p.body}}`
  )
}