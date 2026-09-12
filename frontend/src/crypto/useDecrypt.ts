import { useEffect, useState } from 'react'
import { decrypt, getEcdhKey, looksLikeEnvelope, parseEnvelope } from './e2ee'

export interface DecryptItem {
  id: string
  sender: string
  text: string
  pubPEM: string
}

// cache keeps in-flight / completed decryptions across renders and tab
// switches so rows are only ever decrypted once per session.
const cache = new Map<string, Promise<string | null>>()

async function resolveItem(it: DecryptItem): Promise<string | null> {
  const key = getEcdhKey()
  if (!key) return null
  const env = parseEnvelope(it.text)
  if (!env) return null
  return decrypt(key, it.pubPEM, env)
}

export function pubKeyOf(it: DecryptItem): string | null {
  return it.pubPEM
}

// useDecrypted decrypts the given fields (envelope or plaintext legacy rows)
// and returns a Map id → plaintext. Null marks "could not decrypt".
export function useDecrypted(items: DecryptItem[]): Map<string, string | null> {
  const [resolved, setResolved] = useState<Map<string, string | null>>(new Map())

  useEffect(() => {
    let live = true
    const pending: { it: DecryptItem; prom: Promise<string | null> }[] = []
    for (const it of items) {
      if (resolved.has(it.id)) continue
      if (!looksLikeEnvelope(it.text)) {
        setResolved((prev) => new Map(prev).set(it.id, it.text))
        continue
      }
      const cached = cache.get(it.id)
      const prom = cached ?? resolveItem(it).catch(() => null)
      if (!cached) cache.set(it.id, prom)
      pending.push({ it, prom })
      prom.then((plain) => {
        if (!live) return
        setResolved((prev) => {
          if (prev.get(it.id) === plain) return prev
          const next = new Map(prev)
          next.set(it.id, plain)
          return next
        })
      })
    }
    return () => {
      live = false
    }
  }, [items, resolved])

  return resolved
}