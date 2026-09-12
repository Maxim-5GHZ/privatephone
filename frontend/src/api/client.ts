import { buildWSFrame, signPacket, SignedPacket } from '../crypto/signing'
import type { Snapshot, WSMsg } from '../types'

export async function apiPost(path: string, kind: string, data: unknown): Promise<unknown> {
  const p = await signPacket(kind, data)
  const resp = await fetch(path, { method: 'POST', headers: p.headers, body: p.body })
  const json = await resp.json().catch(() => ({}))
  if (!resp.ok) throw new Error((json as { error?: string }).error ?? `HTTP ${resp.status}`)
  return json
}

export async function apiGet(path: string, kind: string): Promise<unknown> {
  const p = await signPacket(kind, '')
  const resp = await fetch(path, { method: 'GET', headers: p.headers })
  const json = await resp.json().catch(() => ({}))
  if (!resp.ok) throw new Error((json as { error?: string }).error ?? `HTTP ${resp.status}`)
  return json
}

// --- Abonents (CRL) ---

export async function revokeSubscriber(callsign: string, revoke: boolean): Promise<void> {
  await apiPost('/api/v1/ca/revoke', revoke ? 'revoke_subscriber' : 'unrevoke_subscriber', { callsign })
}

// --- Tamper-evident journal (admin) ---

export interface JournalEntry {
  id: string
  sender: string
  kind: string
  payload: string
  signature: string
  nonce: string
  ts: number
  recipient: string
  prev_hash: string
  recv_at: string
}

export interface JournalExport {
  head: string
  entries: JournalEntry[]
}

export async function fetchJournal(after = 0): Promise<JournalExport> {
  const q = after > 0 ? `?after=${after}` : ''
  return (await apiGet(`/api/v1/journal${q}`, 'journal_export')) as JournalExport
}

export async function verifyJournal(): Promise<{ ok: boolean; bad_index: number; head: string }> {
  return (await apiPost('/api/v1/journal/verify', 'journal_verify', {})) as {
    ok: boolean
    bad_index: number
    head: string
  }
}

export interface AdminStats {
  subscribers: number
  active: number
  revoked: number
  online: number
  alerts: number
  journal_entries: number
  journal_head: string
}

export async function fetchAdminStats(): Promise<AdminStats> {
  return (await apiGet('/api/v1/admin/stats', 'admin_stats')) as AdminStats
}

export interface ImportReport {
  added_journal: number
  skipped_duplicates: number
  skipped_context: number
  rejected: boolean
  rejected_at: number
  rejected_why: string
  head: string
}

export async function importJournal(entries: JournalEntry[]): Promise<ImportReport> {
  return (await apiPost('/api/v1/journal/import', 'journal_import', { entries })) as ImportReport
}

export type WSHandler = (msg: WSMsg) => void

export interface WSHandle {
  close: () => void
  send: (p: SignedPacket) => void
}

export function connectWS(onMessage: WSHandler, onState: (open: boolean) => void): WSHandle {
  let closed = false
  let ws: WebSocket | null = null
  let retries = 0

  const open = async () => {
    if (closed) return
    ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/v1/ws`)
    ws.onopen = async () => {
      retries = 0
      onState(true)
      try {
        const hello = await signPacket('hello', {})
        ws?.send(buildWSFrame(hello))
      } catch {
        /* not signed in during reconnect; stays anonymous until next hello */
      }
    }
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as WSMsg
        onMessage(msg)
      } catch {
        /* ignore malformed frame */
      }
    }
    ws.onclose = () => {
      onState(false)
      if (!closed) {
        retries++
        const delay = Math.min(1000 * 2 ** retries, 15000)
        setTimeout(open, delay)
      }
    }
    ws.onerror = () => ws?.close()
  }

  void open()
  return {
    send: (p: SignedPacket) => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(buildWSFrame(p))
    },
    close: () => {
      closed = true
      ws?.close()
    },
  }
}

export async function fetchSnapshot(): Promise<Snapshot> {
  const snap = (await apiGet('/api/v1/snapshot', 'snapshot')) as Snapshot
  return snap
}