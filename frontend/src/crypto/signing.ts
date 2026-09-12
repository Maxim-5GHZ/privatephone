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
  const signature = b64(new Uint8Array(sigBuf))
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