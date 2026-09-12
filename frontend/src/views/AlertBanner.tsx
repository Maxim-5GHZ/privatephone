import { useEffect, useRef } from 'react'
import { playAck, playAlarm } from '../audio'
import { Alert } from '../types'

interface Props {
  alerts: Alert[]
  myCallsign: string
  isAdmin: boolean
  onAck: (a: Alert) => void
  onClear: (a: Alert) => void
}

const ALERT_LABEL: Record<string, string> = { sos: 'SOS', gather: 'СБОР', info: 'Инфо' }

export function AlertBanner({ alerts, myCallsign, isAdmin, onAck, onClear }: Props) {
  const last = alerts[alerts.length - 1]
  const lastKey = last && last.n ? `${last.sender}/${last.n}` : ''
  const prevKey = useRef<string>('')

  useEffect(() => {
    if (lastKey && lastKey !== prevKey.current) {
      prevKey.current = lastKey
      playAlarm()
    }
  }, [lastKey])

  if (!last) return null
  const mine = last.sender === myCallsign
  const acked = (last.acks ?? []).includes(myCallsign)

  return (
    <div className={`alert-banner ${last.type}`}>
      <div className="alert-text">
        <b>{ALERT_LABEL[last.type] ?? last.type}</b> — {last.sender}
        {last.text ? `: ${last.text}` : ''}
        <span className="alert-acks">
          приняли: {last.acks?.length ? last.acks.join(', ') : '—'}
        </span>
      </div>
      <div className="alert-actions">
        {!acked && (
          <button onClick={() => onAck(last)}>
            Принял
          </button>
        )}
        {(mine || isAdmin) && (
          <button className="ghost" onClick={() => onClear(last)}>
            Отбой
          </button>
        )}
      </div>
    </div>
  )
}

export function alertFeedback(): void {
  playAck()
}