import { useEffect, useMemo, useRef, useState } from 'react'
import { b64decode, openFile } from '../crypto/filebox'
import { Chat, FileMeta, Message, Subscriber } from '../types'

interface Props {
  messages: Message[]
  files: FileMeta[]
  messagesMore: boolean
  typing: Map<string, number>
  reads: Map<string, string[]>
  chats: Chat[]
  subscribers: Subscriber[]
  online: string[]
  myCallsign: string
  onSend: (body: string, recipient: string) => Promise<boolean> | void
  onUpdateMessage: (m: Message, body: string) => Promise<boolean>
  onDeleteMessage: (m: Message) => void
  onSendFile: (name: string, mime: string, data: Uint8Array, recipient: string) => Promise<boolean>
  onEnsureBlob: (f: FileMeta) => Promise<FileMeta | null>
  onLoadHistory: () => void
  onTyping: (to: string) => void
  onRead: (to: string, n: string) => void
  onCall: (target: string) => void
}

interface Thread {
  key: string
  title: string
  recipient: string
  isGroup: boolean
  isChat: boolean
  members: string[]
}

function canonicalRecipient(r: string): string {
  if (r === '') return 'general'
  if (r.startsWith('chat:')) return r
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
  return { key, title, recipient: r, isGroup: key.startsWith('g:'), isChat: key.startsWith('chat:'), members }
}

function inThread(t: Thread, recipient: string, sender: string, myCallsign: string): boolean {
  if (t.isChat) return recipient === t.recipient
  if (t.isGroup) return canonicalRecipient(recipient) === t.key
  if (t.recipient === '') return recipient === ''
  return t.recipient === recipient || (recipient === myCallsign && sender === t.recipient)
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} Б`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`
  return `${(n / 1024 / 1024).toFixed(1)} МБ`
}

const VOICE_MAX_MS = 5 * 60 * 1000

export function ChatView({
  messages,
  files,
  messagesMore,
  typing,
  reads,
  chats,
  subscribers,
  online,
  myCallsign,
  onSend,
  onUpdateMessage,
  onDeleteMessage,
  onSendFile,
  onEnsureBlob,
  onLoadHistory,
  onTyping,
  onRead,
  onCall,
}: Props) {
  const [active, setActive] = useState<Thread>(() => threadForRecipient('', 'Общий', [myCallsign]))
  const [body, setBody] = useState('')
  const [showGroup, setShowGroup] = useState(false)
  const [groupPick, setGroupPick] = useState<string[]>([])
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<{ n: string; sender: string; draft: string } | null>(null)
  const [opened, setOpened] = useState<Map<string, string>>(new Map())
  const [opening, setOpening] = useState<string | null>(null)
  const [recording, setRecording] = useState(false)
  const listRef = useRef<HTMLDivElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const recRef = useRef<MediaRecorder | null>(null)
  const recChunks = useRef<Blob[]>([])
  const recTimer = useRef<number | null>(null)
  const typingAt = useRef(0)
  const readSent = useRef<Set<string>>(new Set())

  const threads = useMemo(() => {
    const out: Thread[] = [threadForRecipient('', 'Общий', [myCallsign])]
    // named chats created by admin first
    for (const c of chats) {
      out.push({
        key: `chat:${c.id}`,
        title: `⌖ ${c.name}`,
        recipient: `chat:${c.id}`,
        isGroup: true,
        isChat: true,
        members: c.members,
      })
    }
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
            isChat: false,
            members: members.filter((x) => x !== myCallsign),
          })
        }
      }
    }
    return out
  }, [messages, subscribers, chats, myCallsign])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight })
  }, [messages, files, active.key])

  const threadMessages = useMemo(() => {
    const q = query.trim().toLowerCase()
    return messages.filter((m) => {
      if (!inThread(active, m.recipient, m.sender, myCallsign)) return false
      if (q && !m.body.toLowerCase().includes(q)) return false
      return true
    })
  }, [messages, active, myCallsign, query])

  const threadFiles = useMemo(() => {
    const q = query.trim().toLowerCase()
    return files.filter((f) => {
      if (!inThread(active, f.recipient, f.sender, myCallsign)) return false
      if (q && !f.name.toLowerCase().includes(q)) return false
      return true
    })
  }, [files, active, myCallsign, query])

  type Item = { ts: string; msg?: Message; file?: FileMeta }
  const items = useMemo<Item[]>(() => {
    const out: Item[] = [
      ...threadMessages.map((msg) => ({ msg, ts: msg.created_at || '9999' })),
      ...threadFiles.map((file) => ({ file, ts: file.created_at || '9999' })),
    ]
    out.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0))
    return out
  }, [threadMessages, threadFiles])

  // Peer for DM-only hints (typing goes to a single callsign).
  const dmPeer = !active.isGroup && !active.isChat && active.recipient !== '' ? active.recipient : ''
  const peerTyping = dmPeer !== '' && dmPeer !== myCallsign && (typing.get(dmPeer) ?? 0) > Date.now()

  // Read receipts: tell authors we saw their rows (DM/group/broadcast alike).
  useEffect(() => {
    for (const m of threadMessages) {
      if (m.sender === myCallsign || !m.n) continue
      const key = `${m.sender}|${m.n}`
      if (readSent.current.has(key)) continue
      readSent.current.add(key)
      onRead(m.sender, m.n)
    }
  }, [threadMessages, myCallsign, onRead])

  const send = () => {
    const b = body.trim()
    if (!b) return
    // Keep the draft if sending fails (offline / rejected key): the error
    // is shown via notice, the user retries without retyping.
    const r = onSend(b, active.recipient)
    if (r && typeof (r as Promise<boolean>).then === 'function') {
      void (r as Promise<boolean>).then((ok) => {
        if (ok) setBody('')
      })
    } else {
      setBody('')
    }
  }

  const onBodyChange = (v: string) => {
    setBody(v)
    if (dmPeer && Date.now() - typingAt.current > 3000) {
      typingAt.current = Date.now()
      onTyping(dmPeer)
    }
  }

  const startGroup = () => {
    if (groupPick.length === 0) return
    const members = [...groupPick, myCallsign].sort()
    const recipient = JSON.stringify(members)
    setActive({ key: 'g:' + members.join(','), title: members.filter((x) => x !== myCallsign).join(', '), recipient, isGroup: true, isChat: false, members: members.filter((x) => x !== myCallsign) })
    setShowGroup(false)
    setGroupPick([])
  }

  const pickFile = async (file: File) => {
    const buf = await file.arrayBuffer()
    const bytes = new Uint8Array(buf)
    if (bytes.length > 8 * 1024 * 1024) {
      alert('Файл больше 8 МБ — сожмите перед отправкой')
      return
    }
    await onSendFile(file.name || 'файл', file.type || 'application/octet-stream', bytes, active.recipient)
  }

  const openAttachment = async (f: FileMeta) => {
    const key = `${f.sender}|${f.n}`
    const cached = opened.get(key)
    if (cached) {
      window.open(cached, '_blank', 'noopener')
      return
    }
    if (!f.fileKey) return
    setOpening(key)
    try {
      const full = f.blob ? f : await onEnsureBlob(f)
      if (!full?.blob || !f.fileKey) return
      const plain = await openFile(b64decode(full.blob), b64decode(f.fileKey))
      const url = URL.createObjectURL(new Blob([plain as BlobPart], { type: f.mime }))
      setOpened((prev) => new Map(prev).set(key, url))
      window.open(url, '_blank', 'noopener')
    } finally {
      setOpening(null)
    }
  }

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      const rec = new MediaRecorder(stream, { mimeType: 'audio/webm' })
      recChunks.current = []
      rec.ondataavailable = (e) => {
        if (e.data.size) recChunks.current.push(e.data)
      }
      rec.onstop = () => {
        stream.getTracks().forEach((t) => t.stop())
        setRecording(false)
        if (recTimer.current !== null) {
          window.clearTimeout(recTimer.current)
          recTimer.current = null
        }
        const blob = new Blob(recChunks.current, { type: 'audio/webm' })
        if (blob.size === 0) return
        void blob.arrayBuffer().then((buf) => {
          void onSendFile('голосовое.webm', 'audio/webm', new Uint8Array(buf), active.recipient)
        })
      }
      recRef.current = rec
      rec.start()
      setRecording(true)
      recTimer.current = window.setTimeout(() => rec.stop(), VOICE_MAX_MS)
    } catch {
      alert('Нет доступа к микрофону (нужен HTTPS/TLS и разрешение)')
    }
  }

  const stopRecording = () => {
    recRef.current?.stop()
  }

  const readersOf = (n: string): string[] => reads.get(`${myCallsign}/${n}`) ?? []

  const canCall = !active.isGroup && active.recipient !== '' && active.recipient !== myCallsign && online.includes(active.recipient)

  return (
    <div className="messenger">
      <div className="rail" role="listbox" aria-label="Потоки сообщений">
        <div className="rail-title">Потоки</div>
        {threads.map((t) => (
          <button
            key={t.key}
            type="button"
            role="option"
            aria-selected={t.key === active.key}
            className={`rail-item ${t.key === active.key ? 'active' : ''}`}
            onClick={() => setActive(t)}
          >
            <span className={`dot ${online.includes(t.title) && !t.isGroup ? 'ok' : 'dim'}`} />
            <span className="rail-name">{t.title}</span>
            {!t.isGroup && t.title !== 'Общий' && online.includes(t.title) && <span className="rail-on">онлайн</span>}
          </button>
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
          <span className="muted">
            {active.isChat ? 'чат' : active.isGroup ? 'группа' : active.recipient === '' ? 'всем' : 'директ'}:
          </span>{' '}
          <b>{active.title}</b>
          {active.isChat && <span className="muted"> · {active.members.join(', ')}</span>}
          {peerTyping && <span className="typing">печатает…</span>}
          {canCall && (
            <button className="call-btn" onClick={() => onCall(active.recipient)}>
              Позвонить
            </button>
          )}
          <input
            className="chat-search"
            aria-label="Поиск по переписке"
            placeholder="Поиск…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <div className="chat-list" ref={listRef}>
          {messagesMore && (
            <button className="ghost load-more" onClick={onLoadHistory}>
              Загрузить более ранние
            </button>
          )}
          {items.length === 0 && <p className="muted center">Сообщений пока нет.</p>}
          {items.map((it) => {
            const msg = it.msg
            if (msg) {
              const readers = readersOf(msg.n)
              const isEditing = editing !== null && editing.sender === msg.sender && editing.n === msg.n
              const mine = msg.sender === myCallsign
              return (
              <div key={`m:${msg.sender}:${msg.n}`} className={mine ? 'msg mine' : 'msg'}>
                <span className="phone">{msg.sender}</span>
                {isEditing && editing ? (
                  <span className="edit-box">
                    <input
                      aria-label="Текст правки"
                      value={editing.draft}
                      onChange={(e) => setEditing({ ...editing, draft: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          const d = editing.draft.trim()
                          if (d) {
                            void onUpdateMessage(msg, d).then((ok) => {
                              if (ok) setEditing(null)
                            })
                          }
                        }
                        if (e.key === 'Escape') setEditing(null)
                      }}
                    />
                    <button
                      onClick={() => {
                        const d = editing.draft.trim()
                        if (!d) return
                        void onUpdateMessage(msg, d).then((ok) => {
                          if (ok) setEditing(null)
                        })
                      }}
                    >
                      ✓
                    </button>
                    <button className="ghost" onClick={() => setEditing(null)}>
                      ✕
                    </button>
                  </span>
                ) : (
                  <span className="text">{msg.body}</span>
                )}
                <span className="stamp">
                  {msg.created_at}
                  {msg.edited ? ' · изм.' : ''}
                  {mine && (readers.length > 0 ? ` · ✓✓${readers.length > 1 ? readers.length : ''}` : ' · ✓')}
                </span>
                {mine && !isEditing && (
                  <span className="msg-ops">
                    <button className="pop-btn" title="Изменить" onClick={() => setEditing({ n: msg.n, sender: msg.sender, draft: msg.body })}>
                      изм.
                    </button>
                    <button
                      className="pop-btn danger"
                      title="Удалить"
                      onClick={() => {
                        if (window.confirm('Удалить сообщение?')) onDeleteMessage(msg)
                      }}
                    >
                      ✕
                    </button>
                  </span>
                )}
              </div>
              )
            }
            const file = it.file!
            const fkey = `${file.sender}|${file.n}`
            const fmine = file.sender === myCallsign
            return (
              <div key={`f:${fkey}`} className={fmine ? 'msg mine file-msg' : 'msg file-msg'}>
                <span className="phone">{file.sender}</span>
                <span className="file-card">
                  <span className="file-name">
                    {file.mime.startsWith('audio/') ? '🎤 ' : file.mime.startsWith('image/') ? '🖼 ' : '📎 '}
                    {file.name}
                  </span>
                  <span className="muted"> · {fmtSize(file.size)}</span>
                  {file.fileKey ? (
                    <button
                      className="pop-btn"
                      disabled={opening === fkey}
                      onClick={() => void openAttachment(file)}
                    >
                      {opening === fkey ? '…' : 'Открыть (E2EE)'}
                    </button>
                  ) : (
                    <span className="muted"> · [зашифровано]</span>
                  )}
                </span>
                <span className="stamp">{file.created_at}</span>
              </div>
            )
          })}
        </div>
        <div className="chat-input">
          <label className="sr-only" htmlFor="chat-body">
            Текст сообщения
          </label>
          <input
            id="chat-body"
            aria-label={active.isGroup ? 'Сообщение в группу' : active.recipient === '' ? 'Сообщение всем' : `Сообщение ${active.title}`}
            placeholder={active.isGroup ? 'Сообщение в группу' : active.recipient === '' ? 'Сообщение всем' : `Сообщение ${active.title}`}
            value={body}
            onChange={(e) => onBodyChange(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()}
          />
          <input ref={fileRef} type="file" className="sr-only" aria-label="Прикрепить файл" onChange={(e) => {
            const f = e.target.files?.[0]
            e.target.value = ''
            if (f) void pickFile(f)
          }} />
          <button className="ghost" title="Прикрепить файл (E2EE, до 8 МБ)" onClick={() => fileRef.current?.click()}>
            📎
          </button>
          {recording ? (
            <button className="danger-ghost" title="Остановить и отправить" onClick={stopRecording}>
              ⏺ Стоп
            </button>
          ) : (
            <button className="ghost" title="Голосовое (до 5 мин, E2EE)" onClick={() => void startRecording()}>
              🎤
            </button>
          )}
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
