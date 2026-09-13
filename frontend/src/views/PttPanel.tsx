import { useState } from 'react'

interface Props {
  online: string[]
  myCallsign: string
  session: string[] | null
  talker: string | null
  talkingMe: boolean
  secure: boolean
  onStart: (targets: string[]) => void
  onKey: (on: boolean) => void
  onEnd: () => void
}

const MAX_MEMBERS = 6

function chips(members: string[], myCallsign: string) {
  return [...new Set([myCallsign, ...members])].slice(0, MAX_MEMBERS)
}

export function PttPanel({ online, myCallsign, session, talker, talkingMe, secure, onStart, onKey, onEnd }: Props) {
  const [sel, setSel] = useState<string[]>([])
  const members = chips(session ?? [], myCallsign)

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
        onPointerDown={(e) => {
          e.preventDefault()
          onKey(true)
        }}
        onPointerUp={() => onKey(false)}
        onPointerLeave={() => onKey(false)}
        onPointerCancel={() => onKey(false)}
        onContextMenu={(e) => e.preventDefault()}
      >
        {talkingMe ? 'ГОВОРЮ…' : 'ГОВОРИТЬ (удерживать)'}
      </button>
      <button className="ghost" onClick={onEnd}>
        Завершить
      </button>
    </div>
  )
}