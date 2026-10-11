import { useEffect, useRef } from 'react'
import { playAlarm } from '../audio'
import { Alert } from '../types'

interface Props {
  alerts: Alert[]
  myCallsign: string
  isAdmin: boolean
  onAck: (a: Alert) => void
  onClear: (a: Alert) => void
}

const ALERT_LABEL: Record<string, string> = { sos: 'SOS', gather: 'СБОР', info: 'Инфо' }

// AlertBanner renders the whole queue of active alerts, not just the latest:
// in the field several alarms (SOS + сбор) overlap and the newest must not
// hide the previous ones. The alarm sound fires once per new alert key.
export function AlertBanner({ alerts, myCallsign, isAdmin, onAck, onClear }: Props) {
  const keys = alerts.map((a) => `${a.sender}/${a.n}`).join('|')
  const seen = useRef<Set<string>>(new Set())

  useEffect(() => {
    if (!keys) return
    const fresh = keys.split('|').filter((k) => !seen.current.has(k))
    if (fresh.length) {
      fresh.forEach((k) => seen.current.add(k))
      playAlarm()
    }
  }, [keys])

  if (!alerts.length) return null

  return (
    <div className="alert-queue">
      {alerts.map((a) => {
        const mine = a.sender === myCallsign
        const acked = (a.acks ?? []).includes(myCallsign)
        return (
          <div key={`${a.sender}/${a.n}`} className={`alert-banner ${a.type}`}>
            <div className="alert-text">
              <b>{ALERT_LABEL[a.type] ?? a.type}</b> — {a.sender}
              {a.text ? `: ${a.text}` : ''}
              <span className="alert-acks">
                приняли: {a.acks?.length ? a.acks.join(', ') : '—'}
              </span>
            </div>
            <div className="alert-actions">
              {!acked && (
                <button onClick={() => onAck(a)}>
                  Принял
                </button>
              )}
              {(mine || isAdmin) && (
                <button className="ghost" onClick={() => onClear(a)}>
                  Отбой
                </button>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}