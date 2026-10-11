export interface Marker {
  id: number
  sender: string
  lat: number
  lon: number
  type: string
  desc: string
  n: string
  created_at: string
  inactive?: number
}

export interface Alert {
  id: number
  sender: string
  type: string
  text?: string
  n: string
  created_at: string
  acks?: string[]
}

export interface Zone {
  id: number
  sender: string
  name: string
  color: string
  points: string
  n: string
  created_at: string
}

export interface Message {
  id: number
  sender: string
  recipient: string
  body: string
  n: string
  created_at: string
  edited?: number
}

// FileMeta is one E2EE file/voice attachment. blob (base64 ciphertext) is
// present on live/pending/downloaded rows; snapshot rows carry metadata only.
// fileKey (base64) is resolved client-side from the e2ee envelope.
export interface FileMeta {
  id: number
  sender: string
  recipient: string
  name: string
  mime: string
  size: number
  blob?: string
  enc: string
  n: string
  created_at: string
  fileKey?: string | null
}

export interface Chat {
  id: string
  name: string
  members: string[]
  creator: string
  created_at: string
}

export interface Subscriber {
  id: string
  callsign: string
  role: string
  pubkey: string
  revoked?: number
}

export interface Packet {
  id: string
  sender: string
  kind: string
  payload: string
  signature: string
  nonce: string
  ts: number
  recipient?: string
}

export interface Snapshot {
  markers: Marker[]
  messages: Message[]
  messages_more?: boolean
  files?: FileMeta[]
  alerts?: Alert[]
  zones?: Zone[]
  chats?: Chat[]
  online: string[]
}

export interface SdpData {
  type: string
  sdp: string
}

export interface IceCandidate {
  candidate?: string
  sdpMid?: string | null
  sdpMLineIndex?: number | null
}

// server-pushed or relayed (signed) messages over the WebSocket
export type WSMsg =
  | { kind: 'snapshot'; data: Snapshot }
  | { kind: 'packets'; data: { items: Packet[] } }
  | { kind: 'marker'; data: Marker }
  | { kind: 'marker_updated'; data: Marker }
  | { kind: 'marker_deleted'; data: { sender: string; n: string; id?: number } }
  | { kind: 'message'; data: Message }
  | { kind: 'message_updated'; data: Message }
  | { kind: 'message_deleted'; data: { sender: string; n: string; id?: number } }
  | { kind: 'file'; data: FileMeta }
  | { kind: 'typing'; sender: string; data: { to: string } }
  | { kind: 'message_read'; sender: string; data: { to: string; n: string } }
  | { kind: 'chat_created'; data: Chat }
  | { kind: 'chat_updated'; data: Chat }
  | { kind: 'chat_deleted'; data: { id: string } }
  | { kind: 'alert'; data: Alert }
  | { kind: 'alert_acks'; data: { id: number; author: string; n: string; sender: string } }
  | { kind: 'alert_cleared'; data: { id: number; author: string; n: string; by: string } }
  | { kind: 'zone'; data: Zone }
  | { kind: 'zone_updated'; data: Zone }
  | { kind: 'zone_deleted'; data: { sender: string; n: string; id?: number } }
  | { kind: 'presence'; data: { online: string[] } }
  | { kind: 'call_invite'; sender: string; data: { to: string; enc?: unknown } }
  | { kind: 'call_accept'; sender: string; data: { to: string; enc?: unknown } }
  | { kind: 'call_reject'; sender: string; data: { to: string } }
  | { kind: 'call_bye'; sender: string; data: { to: string } }
  | { kind: 'ice'; sender: string; data: { to: string; enc?: unknown } }
  | {
      kind: 'ptt_start' | 'ptt_end' | 'ptt_talking' | 'ptt_offer' | 'ptt_answer' | 'ptt_ice'
      sender: string
      data: {
        n?: string
        to?: string | string[]
        talks?: string
        /** sealed SDP/ICE/SFrame-share envelope (see crypto/signal.ts) */
        enc?: unknown
      }
    }
  | { kind: 'call_error'; data: { to: string; error?: string } }
  | { kind: string; data: unknown }

export type CallState = 'idle' | 'calling' | 'ringing' | 'connecting' | 'in-call' | 'ended'

export const MARKER_COLORS: Record<string, string> = {
  own: '#2e7d32',
  enemy: '#c62828',
  neutral: '#6a1b9a',
  rex: '#ef6c00',
  medic: '#e53935',
  people: '#00897b',
  vehicle: '#1976d2',
  meet: '#7cb342',
  other: '#546e7a',
}

export const MARKER_LABELS = [
  { value: 'own', label: 'Свои' },
  { value: 'enemy', label: 'Противник' },
  { value: 'neutral', label: 'Нейтральная' },
  { value: 'rex', label: 'РЭБ' },
  { value: 'medic', label: 'Раненый' },
  { value: 'people', label: 'Люди' },
  { value: 'vehicle', label: 'Техника' },
  { value: 'meet', label: 'Встреча' },
  { value: 'other', label: 'Другое' },
]

// one-tap favourites for quick placing on the map
export const MARKER_QUICK = ['enemy', 'rex', 'medic', 'own', 'meet']

export const MARKER_LABEL: Record<string, string> = Object.fromEntries(MARKER_LABELS.map((o) => [o.value, o.label]))

export function timeAgo(iso: string): string {
  const t = new Date(iso).getTime()
  if (!t) return ''
  const s = Math.floor((Date.now() - t) / 1000)
  if (s < 60) return 'только что'
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`
  if (s < 86400) return `${Math.floor(s / 3600)} ч назад`
  return `${Math.floor(s / 86400)} дн назад`
}