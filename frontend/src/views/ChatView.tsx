import { useEffect, useMemo, useRef, useState } from 'react'
import { Message, Subscriber } from '../types'

interface Props {
  messages: Message[]
  subscribers: Subscriber[]
  online: string[]
  myCallsign: string
  onSend: (body: string, recipient: string) => void
  onCall: (target: string) => void
}

interface Thread {
  key: string
  title: string
  recipient: string
  isGroup: boolean
  members: string[]
}

function canonicalRecipient(r: string): string {
  if (r === '') return 'general'
  if (r[0] === '[') {
    try {
      const list = JSON.parse(r) as string[]
      return 'g:' + list.slice().sort().join(',')
    } catch {
      return 'dm:' + r
    }
  }
  return 'dm:' + r
}

function threadForRecipient(r: string, title: string, members: string[]): Thread {
  const key = canonicalRecipient(r)
  return { key, title, recipient: r, isGroup: key.startsWith('g:'), members }
}

export function ChatView({ messages, subscribers, online, myCallsign, onSend, onCall }: Props) {
  const [active, setActive] = useState<Thread>(() => threadForRecipient('', 'Общий', [myCallsign]))
  const [body, setBody] = useState('')
  const [showGroup, setShowGroup] = useState(false)
  const [groupPick, setGroupPick] = useState<string[]>([])
  const listRef = useRef<HTMLDivElement>(null)

  const threads = useMemo(() => {
    const out: Thread[] = [threadForRecipient('', 'Общий', [myCallsign])]
    const groupSeen = new Set<string>()
    for (const s of subscribers) {
      if (s.callsign !== myCallsign) {
        out.push(threadForRecipient(s.callsign, s.callsign, [myCallsign, s.callsign]))
      }
    }
    for (const m of messages) {
      const r = m.recipient
      if (r !== '' && r[0] === '[') {
        const members = canonicalMembers(r)
        if (!members) continue
        const key = 'g:' + members.slice().sort().join(',')
        if (!groupSeen.has(key)) {
          groupSeen.add(key)
          out.push({
            key,
            title: members.join(', '),
            recipient: r,
            isGroup: true,
            members: members.filter((x) => x !== myCallsign),
          })
        }
      }
    }
    return out
  }, [messages, subscribers, myCallsign])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight })
  }, [messages, active.key])

  const threadMessages = useMemo(() => {
    return messages.filter((m) => {
      const key = canonicalRecipient(m.recipient)
      if (active.isGroup) {
        return key === active.key
      }
      if (active.recipient === '') return m.recipient === ''
      // direct: to target from me, or from target to me
      return active.recipient === m.recipient || (m.recipient === myCallsign && m.sender === active.recipient)
    })
  }, [messages, active, myCallsign])

  const send = () => {
    const b = body.trim()
    if (!b) return
    onSend(b, active.recipient)
    setBody('')
  }

  const startGroup = () => {
    if (groupPick.length === 0) return
    const members = [...groupPick, myCallsign].sort()
    const recipient = JSON.stringify(members)
    setActive({ key: 'g:' + members.join(','), title: members.filter((x) => x !== myCallsign).join(', '), recipient, isGroup: true, members: members.filter((x) => x !== myCallsign) })
    setShowGroup(false)
    setGroupPick([])
  }

  const canCall = !active.isGroup && active.recipient !== '' && active.recipient !== myCallsign && online.includes(active.recipient)

  return (
    <div className="messenger">
      <div className="rail">
        <div className="rail-title">Потоки</div>
        {threads.map((t) => (
          <div key={t.key} className={`rail-item ${t.key === active.key ? 'active' : ''}`} onClick={() => setActive(t)}>
            <span className={`dot ${online.includes(t.title) && !t.isGroup ? 'ok' : 'dim'}`} />
            <span className="rail-name">{t.title}</span>
            {!t.isGroup && t.title !== 'Общий' && online.includes(t.title) && <span className="rail-on">онлайн</span>}
          </div>
        ))}
        <button className="ghost" onClick={() => setShowGroup((v) => !v)}>
          Новая группа
        </button>
        {showGroup && (
          <div className="group-pick">
            {subscribers
              .filter((s) => s.callsign !== myCallsign)
              .map((s) => (
                <label key={s.callsign} className="row">
                  <input
                    type="checkbox"
                    checked={groupPick.includes(s.callsign)}
                    onChange={(e) =>
                      setGroupPick((prev) => (e.target.checked ? [...prev, s.callsign] : prev.filter((c) => c !== s.callsign)))
                    }
                  />
                  {s.callsign}
                </label>
              ))}
            <button onClick={startGroup} disabled={groupPick.length === 0}>
              Начать
            </button>
          </div>
        )}
      </div>

      <div className="chat-area">
        <div className="chat-head">
          <span className="muted">{active.isGroup ? 'группа' : active.recipient === '' ? 'всем' : 'директ'}:</span>{' '}
          <b>{active.title}</b>
          {canCall && (
            <button className="call-btn" onClick={() => onCall(active.recipient)}>
              Позвонить
            </button>
          )}
        </div>
        <div className="chat-list" ref={listRef}>
          {threadMessages.length === 0 && <p className="muted center">Сообщений пока нет.</p>}
          {threadMessages.map((m) => (
            <div key={`${m.sender}:${m.n}`} className={m.sender === myCallsign ? 'msg mine' : 'msg'}>
              <span className="phone">{m.sender}</span>
              <span className="text">{m.body}</span>
              <span className="stamp">{m.created_at}</span>
            </div>
          ))}
        </div>
        <div className="chat-input">
          <input
            placeholder={active.isGroup ? 'Сообщение в группу' : active.recipient === '' ? 'Сообщение всем' : `Сообщение ${active.title}`}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()}
          />
          <button onClick={send}>Отправить</button>
        </div>
      </div>
    </div>
  )
}

function canonicalMembers(r: string): string[] | null {
  try {
    const list = JSON.parse(r) as string[]
    if (Array.isArray(list) && list.length > 0) return list
  } catch {
    /* not a group */
  }
  return null
}