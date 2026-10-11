import { useState } from 'react'
import { CALL_RESULT_LABEL, CallLogEntry, TalkMark } from '../call/log'

interface Props {
  online: string[]
  myCallsign: string
  session: string[] | null
  talker: string | null
  talkingMe: boolean
  secure: boolean
  recent: TalkMark[]
  callLog: CallLogEntry[]
  onClearLog: () => void
  onStart: (targets: string[]) => void
  onKey: (on: boolean) => void
  onEnd: () => void
}

const MAX_MEMBERS = 6

function chips(members: string[], myCallsign: string) {
  return [...new Set([myCallsign, ...members])].slice(0, MAX_MEMBERS)
}

export function PttPanel({ online, myCallsign, session, talker, talkingMe, secure, recent, callLog, onClearLog, onStart, onKey, onEnd }: Props) {
  const [sel, setSel] = useState<string[]>([])
  // Lock mode: once engaged, the transmission stays on even if the finger
  // slides off the button (glove use); tap again to release.
  const [locked, setLocked] = useState(false)
  const members = chips(session ?? [], myCallsign)

  const keyDown = () => {
    if (locked) {
      setLocked(false)
      onKey(false)
      return
    }
    onKey(true)
  }

  if (!session) {
    const selectorList = online.filter((o) => o !== myCallsign).sort()
    const toggle = (c: string) => {
      setSel((prev) => {
        if (prev.includes(c)) return prev.filter((x) => x !== c)
        if (prev.length >= MAX_MEMBERS - 1) return prev
        return [...prev, c]
      })
    }
    return (
      <div className="ptt-panel">
        <h3>
          Рация (до {MAX_MEMBERS} абонентов)
          {secure ? <span className="lock">{'\u{1F512}'} E2EE</span> : <span className="lock warn">без E2EE</span>}
        </h3>
        {selectorList.length === 0 ? (
          <p className="muted">Сейчас в сети только вы.</p>
        ) : (
          <div className="ptt-list">
            {selectorList.map((c) => (
              <label key={c} className={sel.includes(c) ? 'on' : ''}>
                <input type="checkbox" checked={sel.includes(c)} onChange={() => toggle(c)} />
                {c}
              </label>
            ))}
          </div>
        )}
        <div className="row">
          <button disabled={sel.length === 0} onClick={() => onStart(sel)}>
            Начать сеанс
          </button>
        </div>
        <p className="muted">Голос идёт напрямую между абонентами (одна ЛВС), мимо сервера медиа.</p>
        <HistoryBlock log={callLog} onClear={onClearLog} />
      </div>
    )
  }

  return (
    <div className="ptt-panel active">
      <div className="ptt-members">
        {members.map((m) => (
          <span key={m} className={m === talker ? 'talk' : ''}>
            {m}
            {m === talker ? ' 🎙' : ''}
          </span>
        ))}
      </div>
      <div className="ptt-talker muted">{talker ? `Говорит: ${talker}` : 'Свободно'}</div>
      <button
        className={`ptt-talk ${talkingMe ? 'on' : ''}`}
        aria-pressed={talkingMe}
        aria-label={locked ? 'Передача зафиксирована, нажмите чтобы отпустить' : 'Говорить — удерживать или зафиксировать'}
        onPointerDown={(e) => {
          e.preventDefault()
          keyDown()
        }}
        onPointerUp={() => {
          if (!locked) onKey(false)
        }}
        onPointerLeave={() => {
          // Without lock a slide-off ends the transmission; with lock it stays.
          if (!locked) onKey(false)
        }}
        onPointerCancel={() => {
          if (!locked) onKey(false)
        }}
        onContextMenu={(e) => e.preventDefault()}
      >
        {talkingMe ? (locked ? 'ГОВОРЮ (фикс) — жми' : 'ГОВОРЮ…') : 'ГОВОРИТЬ (удерживать)'}
      </button>
      <div className="row">
        <button
          className={`ghost ${locked ? 'active' : ''}`}
          onClick={() => {
            if (locked) {
              setLocked(false)
              onKey(false)
            } else {
              setLocked(true)
              onKey(true)
            }
          }}
          title="Зафиксировать передачу (для перчаток)"
        >
          {locked ? 'Отпустить фикс' : 'Фикс передачи'}
        </button>
        <button className="ghost" onClick={onEnd}>
          Завершить
        </button>
      </div>
      {recent.length > 0 && (
        <div className="ptt-queue" aria-live="polite">
          <div className="muted">Эфир: {recent.map((t) => t.who).join(' → ')}</div>
        </div>
      )}
      <HistoryBlock log={callLog} onClear={onClearLog} />
    </div>
  )
}

// HistoryBlock shares the radio dock: the PTT queue lives above (in-session),
// the handset's own call journal below (server relay is ephemeral).
function HistoryBlock({ log, onClear }: { log: CallLogEntry[]; onClear: () => void }) {
  if (!log.length) return <p className="muted">Вызовов пока нет.</p>
  const last = log.slice(-8).reverse()
  return (
    <div className="call-log">
      <div className="row call-log-head">
        <span className="muted">Вызовы</span>
        <button className="pop-btn" onClick={onClear} title="Очистить историю на этом устройстве">
          Очистить
        </button>
      </div>
      {last.map((e, i) => (
        <div key={`${e.at}-${i}`} className="call-log-row">
          <span>{e.dir === 'in' ? '↙' : '↗'}</span>
          <span className="phone">{e.peer}</span>
          <span className="muted">{CALL_RESULT_LABEL[e.result]}</span>
          <span className="muted">{new Date(e.at).toLocaleTimeString()}</span>
        </div>
      ))}
    </div>
  )
}