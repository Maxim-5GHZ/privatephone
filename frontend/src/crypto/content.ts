// Content-addressing helpers shared by the UI and its unit tests.

// recipientList turns the wire "recipient" field into a set of callsigns.
// "" means broadcast, a single callsign is direct, a JSON array is a group.
export function recipientList(r: string): string[] {
  if (!r) return []
  try {
    const arr = JSON.parse(r) as unknown
    if (Array.isArray(arr)) return arr as string[]
  } catch {
    /* single recipient */
  }
  return [r]
}

// encId builds the content-based id for the decrypt cache: marker/zone/alert
// updates reuse the same nonce but carry a fresh envelope, so keying on
// (sender, n) would serve stale plaintext. Hashing the content ties the cache
// entry to the exact ciphertext the UI is holding.
export function encId(kind: string, sender: string, text: string): string {
  let h = 5381
  for (let i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) | 0
  return `${kind}:${sender}:${text.length}:${h}`
}