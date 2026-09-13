import { useEffect, useRef } from 'react'
import { CallState } from '../types'

export interface CallUi {
  state: CallState
  peer: string | null
  incoming: boolean
  error: string | null
}

interface Props {
  call: CallUi
  remote: MediaStream | null
  secure: boolean
  onAccept: () => void
  onReject: () => void
  onHangup: () => void
}

export function CallOverlay({ call, remote, secure, onAccept, onReject, onHangup }: Props) {
  const audioRef = useRef<HTMLAudioElement>(null)

  useEffect(() => {
    const el = audioRef.current
    if (el && remote) {
      el.srcObject = remote
      void el.play().catch(() => {})
    }
  }, [remote])

  if (call.state === 'idle' || call.state === 'ended') {
    return call.error ? (
      <div className="notice" onClick={onHangup}>
        {call.error}
      </div>
    ) : null
  }

  const ringing = call.incoming && call.state === 'ringing'

  return (
    <div className="call-overlay">
      <div className="call-card">
        <h2>{ringing ? 'Входящий вызов' : 'Вызов'}</h2>
        <p className="phone">{call.peer ?? ''}</p>
        <p className="muted">
          {call.state === 'calling' || call.state === 'connecting' || call.state === 'in-call'
            ? `${secure ? '\u{1F512} E2EE' : 'без E2EE'} · `
            : ''}
          {ringing
            ? 'Пользователь звонит вам…'
            : call.state === 'calling'
              ? 'Звоним…'
              : call.state === 'connecting'
                ? 'Соединяем…'
                : 'Разговор идёт'}
        </p>
        {call.error && <p className="error">{call.error}</p>}
        <div className="call-actions">
          {ringing ? (
            <>
              <button onClick={onAccept}>Принять</button>
              <button className="danger-ghost" onClick={onReject}>
                Отклонить
              </button>
            </>
          ) : call.state === 'calling' ? (
            <button className="danger-ghost" onClick={onHangup}>
              Отменить
            </button>
          ) : call.state === 'in-call' || call.state === 'connecting' ? (
            <button className="danger-ghost" onClick={onHangup}>
              Положить трубку
            </button>
          ) : (
            <button className="danger-ghost" onClick={onHangup}>
              Завершить
            </button>
          )}
        </div>
        <audio ref={audioRef} autoPlay />
      </div>
    </div>
  )
}