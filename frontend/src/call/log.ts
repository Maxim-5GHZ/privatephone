// Call + PTT history helpers (local-only, per callsign). Call signaling stays
// ephemeral on the server (relay, unjournaled), so the handset keeps its own
// journal in localStorage: who called whom and with what outcome, plus the
// recent PTT talker queue. Pure functions for testability; storage key is
// namespaced by callsign so shared tablets don't leak history across logins.
export interface CallLogEntry {
  peer: string
  dir: 'in' | 'out'
  result: 'calling' | 'ringing' | 'accepted' | 'rejected' | 'missed' | 'ended' | 'offline'
  at: number
}

export interface TalkMark {
  who: string
  at: number
}

export const CALL_LOG_CAP = 50
export const TALK_QUEUE_CAP = 5

export function callLogKey(callsign: string): string {
  return `pp.calllog.${callsign}`
}

export function loadCallLog(callsign: string): CallLogEntry[] {
  try {
    const raw = localStorage.getItem(callLogKey(callsign))
    if (!raw) return []
    const arr = JSON.parse(raw) as CallLogEntry[]
    if (!Array.isArray(arr)) return []
    return arr.filter((e) => typeof e?.peer === 'string' && typeof e?.at === 'number').slice(-CALL_LOG_CAP)
  } catch {
    return []
  }
}

export function appendCallLog(callsign: string, entry: CallLogEntry): CallLogEntry[] {
  const next = [...loadCallLog(callsign), entry].slice(-CALL_LOG_CAP)
  try {
    localStorage.setItem(callLogKey(callsign), JSON.stringify(next))
  } catch {
    /* storage full/blocked — history stays in memory */
  }
  return next
}

export function clearCallLog(callsign: string): void {
  try {
    localStorage.removeItem(callLogKey(callsign))
  } catch {
    /* ignore */
  }
}

// pushTalker keeps the last talkers, newest last, skipping a consecutive
// duplicate (holding the mic fires repeated talking frames).
export function pushTalker(queue: TalkMark[], who: string, at = Date.now()): TalkMark[] {
  if (!who) return queue
  if (queue.length && queue[queue.length - 1].who === who) return queue
  return [...queue, { who, at }].slice(-TALK_QUEUE_CAP)
}

export const CALL_RESULT_LABEL: Record<CallLogEntry['result'], string> = {
  calling: 'исходящий…',
  ringing: 'входящий…',
  accepted: 'разговор',
  rejected: 'отклонён',
  missed: 'пропущенный',
  ended: 'завершён',
  offline: 'абонент офлайн',
}
