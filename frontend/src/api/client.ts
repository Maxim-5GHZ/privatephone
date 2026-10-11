import { buildWSFrame, signPacket, SignedPacket } from '../crypto/signing'
import type { Snapshot, WSMsg } from '../types'

// encodeFetchHeaders percent-encodes X-Sender so non-ASCII callsigns
// (e.g. Cyrillic) stay valid ByteString header values. fetch() throws
// "has value 1073 which is greater than 255" for raw Cyrillic.
// Latin callsigns are unchanged by encodeURIComponent (backward compatible);
// the server PathUnescapes back to the raw callsign before verification.
// WS frames are JSON (UTF-8) and keep the raw sender — only fetch headers
// need this.
function encodeFetchHeaders(h: Record<string, string>): Record<string, string> {
  if (!h['X-Sender']) return h
  return { ...h, 'X-Sender': encodeURIComponent(h['X-Sender']) }
}

export async function apiPost(path: string, kind: string, data: unknown): Promise<unknown> {
  const p = await signPacket(kind, data)
  const resp = await fetch(path, { method: 'POST', headers: encodeFetchHeaders(p.headers), body: p.body })
  const json = await resp.json().catch(() => ({}))
  if (!resp.ok) throw new Error((json as { error?: string }).error ?? `HTTP ${resp.status}`)
  return json
}

export async function apiGet(path: string, kind: string): Promise<unknown> {
  const p = await signPacket(kind, '')
  const resp = await fetch(path, { method: 'GET', headers: encodeFetchHeaders(p.headers) })
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

export interface HistoryPage {
  messages: { id: number; sender: string; recipient: string; body: string; n: string; created_at: string; edited?: number }[]
  more: boolean
}

export async function fetchHistory(beforeId: number, limit = 50): Promise<HistoryPage> {
  const q = `?limit=${limit}${beforeId > 0 ? `&before_id=${beforeId}` : ''}`
  return (await apiGet(`/api/v1/messages${q}`, 'history')) as HistoryPage
}

export async function fetchFile(sender: string, n: string): Promise<{
  id: number
  sender: string
  recipient: string
  name: string
  mime: string
  size: number
  blob: string
  enc: string
  n: string
  created_at: string
}> {
  const q = `?sender=${encodeURIComponent(sender)}&n=${encodeURIComponent(n)}`
  return (await apiGet(`/api/v1/files${q}`, 'file_get')) as {
    id: number
    sender: string
    recipient: string
    name: string
    mime: string
    size: number
    blob: string
    enc: string
    n: string
    created_at: string
  }
}

// --- Named chats (admin creates, members read/write) ---

export interface ChatDTO {
  id: string
  name: string
  members: string[]
  creator: string
  created_at: string
}

export async function fetchChats(): Promise<ChatDTO[]> {
  const out = (await apiGet('/api/v1/chats', 'list_chats')) as { chats: ChatDTO[] }
  return out.chats ?? []
}

export async function createChat(name: string, members: string[]): Promise<ChatDTO> {
  return (await apiPost('/api/v1/chats', 'chat_create', { name, members })) as ChatDTO
}

export async function updateChat(id: string, name: string, members: string[]): Promise<ChatDTO> {
  return (await apiPost('/api/v1/chats', 'chat_update', { id, name, members })) as ChatDTO
}

export async function deleteChat(id: string): Promise<void> {
  await apiPost('/api/v1/chats', 'chat_delete', { id })
}

// --- Custom offline tiles (admin uploads) ---

export interface TilesStatus {
  custom_tiles: number
  custom_bytes: number
  by_source?: { osm: number; sat: number }
}

export async function fetchTilesStatus(): Promise<TilesStatus> {
  return (await apiGet('/api/v1/admin/tiles/status', 'tiles_status')) as TilesStatus
}

export type TileSource = 'osm' | 'sat'

export interface TilesFetchStatus {
  state: 'idle' | 'running' | 'done' | 'error'
  source?: string
  done: number
  total: number
  error?: string
}

export async function startTilesFetch(req: {
  source: TileSource
  lat: number
  lon: number
  zmin: number
  zmax: number
  span: number
}): Promise<{ started: boolean; total: number; source: string }> {
  return (await apiPost('/api/v1/admin/tiles/fetch', 'tiles_fetch', req)) as {
    started: boolean
    total: number
    source: string
  }
}

export async function fetchTilesFetchStatus(): Promise<TilesFetchStatus> {
  return (await apiGet('/api/v1/admin/tiles/fetch/status', 'tiles_fetch_status')) as TilesFetchStatus
}

function arrayBufferToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let bin = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(bin)
}

export async function uploadTile(z: number, x: number, y: number, file: Blob, source: TileSource = 'osm'): Promise<void> {
  const buf = await file.arrayBuffer()
  const png_b64 = arrayBufferToB64(buf)
  await apiPost('/api/v1/admin/tiles', 'tiles_put', { z, x, y, png_b64, source })
}

export async function uploadTilesBag(file: Blob, source: TileSource = 'osm'): Promise<{ added: number; skipped: number }> {
  const buf = await file.arrayBuffer()
  const zip_b64 = arrayBufferToB64(buf)
  return (await apiPost('/api/v1/admin/tiles/bag', 'tiles_bag', { zip_b64, source })) as { added: number; skipped: number }
}

export async function clearTiles(): Promise<void> {
  await apiPost('/api/v1/admin/tiles/clear', 'tiles_clear', {})
}