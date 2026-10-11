// filebox: E2EE file/voice payload crypto. The file bytes are sealed with a
// fresh random fileKey (AES-GCM); the key itself travels inside the regular
// e2ee v2 envelope (JSON {k, name, mime, size}) addressed to the recipients,
// so the node only ever sees opaque ciphertext + envelope.
export function b64encode(raw: Uint8Array): string {
  let bin = ''
  const chunk = 0x8000
  for (let i = 0; i < raw.length; i += chunk) {
    bin += String.fromCharCode(...raw.subarray(i, i + chunk))
  }
  return btoa(bin)
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export interface SealedFile {
  /** iv(12) || ciphertext */
  raw: Uint8Array
  fileKey: Uint8Array
}

export async function sealFile(data: Uint8Array): Promise<SealedFile> {
  const fileKey = new Uint8Array(32)
  crypto.getRandomValues(fileKey)
  const iv = new Uint8Array(12)
  crypto.getRandomValues(iv)
  const key = await crypto.subtle.importKey('raw', fileKey as BufferSource, { name: 'AES-GCM' }, false, ['encrypt'])
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, data as BufferSource)
  const raw = new Uint8Array(12 + ct.byteLength)
  raw.set(iv, 0)
  raw.set(new Uint8Array(ct), 12)
  return { raw, fileKey }
}

export async function openFile(raw: Uint8Array, fileKey: Uint8Array): Promise<Uint8Array> {
  const iv = raw.subarray(0, 12)
  const ct = raw.subarray(12)
  const key = await crypto.subtle.importKey('raw', fileKey as BufferSource, { name: 'AES-GCM' }, false, ['decrypt'])
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ct as BufferSource)
  return new Uint8Array(plain)
}

export interface FileKeyInfo {
  k: string
  name: string
  mime: string
  size: number
}

export function parseFileKey(plaintext: string): FileKeyInfo | null {
  try {
    const o = JSON.parse(plaintext) as Partial<FileKeyInfo>
    if (typeof o.k !== 'string' || !o.k) return null
    return { k: o.k, name: typeof o.name === 'string' ? o.name : 'файл', mime: typeof o.mime === 'string' ? o.mime : 'application/octet-stream', size: typeof o.size === 'number' ? o.size : 0 }
  } catch {
    return null
  }
}
