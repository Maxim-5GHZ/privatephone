import { useEffect, useState } from 'react'
import { Chat, Subscriber } from '../types'
import {
  clearTiles,
  fetchJournal,
  fetchAdminStats,
  fetchTilesFetchStatus,
  fetchTilesStatus,
  importJournal,
  startTilesFetch,
  uploadTile,
  uploadTilesBag,
  AdminStats,
  ImportReport,
  JournalEntry,
  TileSource,
  TilesFetchStatus,
  TilesStatus,
  verifyJournal,
} from '../api/client'
import { fingerprint, isE2eeArmed } from '../crypto/e2ee'

interface Props {
  subscribers: Subscriber[]
  chats: Chat[]
  isAdmin: boolean
  onCreate: (callsign: string, role: string) => Promise<string | null> // returns private pem or null
  onRefresh: () => void
  onRevoke: (callsign: string, revoke: boolean) => Promise<void>
  onChatCreate: (name: string, members: string[]) => Promise<void>
  onChatUpdate: (id: string, name: string, members: string[]) => Promise<void>
  onChatDelete: (id: string) => Promise<void>
  onChatsRefresh: () => void
}

type Section = 'subs' | 'chats' | 'maps' | 'journal' | 'import'

export function AdminView({
  subscribers,
  chats,
  isAdmin,
  onCreate,
  onRefresh,
  onRevoke,
  onChatCreate,
  onChatUpdate,
  onChatDelete,
  onChatsRefresh,
}: Props) {
  const [section, setSection] = useState<Section>('subs')
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [statsErr, setStatsErr] = useState<string | null>(null)

  const loadStats = async () => {
    try {
      setStats(await fetchAdminStats())
      setStatsErr(null)
    } catch (e) {
      const msg = (e as Error).message
      setStatsErr(
        /401|signature|unauthorized/i.test(msg)
          ? `Сервер ключ не принял (${msg}): войдите файлом admin.pem из data-каталога ЭТОГО узла (рядом с vault.db из строки «мастер-ключ из половин» в логе).`
          : msg,
      )
    }
  }
  useEffect(() => {
    void loadStats()
  }, [])

  const cards: { label: string; value: string; tone?: string }[] = stats
    ? [
        { label: 'Абонентов', value: String(stats.subscribers) },
        { label: 'Активны', value: String(stats.active) },
        { label: 'Отозваны', value: String(stats.revoked), tone: stats.revoked ? 'danger' : undefined },
        { label: 'В сети', value: String(stats.online) },
        { label: 'Тревог', value: String(stats.alerts), tone: stats.alerts ? 'accent' : undefined },
        { label: 'Пакетов в журнале', value: String(stats.journal_entries) },
      ]
    : []

  return (
    <div className="admin">
      <div className="admin-head">
        <h2>Дашборд оператора</h2>
        <span className={`badge ${isE2eeArmed() ? 'ok' : 'warn'}`}>
          контент: {isE2eeArmed() ? 'E2EE активен' : 'не расшифрован'}
        </span>
      </div>

      <div className="stats-grid">
        {statsErr ? (
          <p className="error">{statsErr}</p>
        ) : (
          cards.map((c) => (
            <div key={c.label} className={`stat-card${c.tone ? ` ${c.tone}` : ''}`}>
              <div className="stat-value">{stats ? c.value : '…'}</div>
              <div className="stat-label">{c.label}</div>
            </div>
          ))
        )}
      </div>
      <div className="row">
        <button className="ghost" onClick={() => void loadStats()}>
          Обновить сводку
        </button>
      </div>

      <div className="row tabs">
        <button className={section === 'subs' ? 'active' : 'ghost'} onClick={() => setSection('subs')}>
          Абоненты
        </button>
        <button className={section === 'chats' ? 'active' : 'ghost'} onClick={() => setSection('chats')}>
          Чаты
        </button>
        <button className={section === 'maps' ? 'active' : 'ghost'} onClick={() => setSection('maps')}>
          Карты
        </button>
        <button className={section === 'journal' ? 'active' : 'ghost'} onClick={() => setSection('journal')}>
          Журнал
        </button>
        <button className={section === 'import' ? 'active' : 'ghost'} onClick={() => setSection('import')}>
          Импорт с УСБ
        </button>
      </div>

      {section === 'subs' && (
        <SubscribersTab
          subscribers={subscribers}
          isAdmin={isAdmin}
          onRefresh={onRefresh}
          onRevoke={onRevoke}
          create={(c, r) => onCreate(c, r)}
        />
      )}
      {section === 'chats' && (
        <ChatsTab
          chats={chats}
          subscribers={subscribers}
          isAdmin={isAdmin}
          onCreate={onChatCreate}
          onUpdate={onChatUpdate}
          onDelete={onChatDelete}
          onRefresh={onChatsRefresh}
        />
      )}
      {section === 'maps' && <MapsTab isAdmin={isAdmin} />}
      {section === 'journal' && <JournalTab isAdmin={isAdmin} />}
      {section === 'import' && <ImportTab isAdmin={isAdmin} />}
    </div>
  )
}

function SubscribersTab({
  subscribers,
  isAdmin,
  onRefresh,
  onRevoke,
  create,
}: {
  subscribers: Subscriber[]
  isAdmin: boolean
  onRefresh: () => void
  onRevoke: (callsign: string, revoke: boolean) => Promise<void>
  create: (callsign: string, role: string) => Promise<string | null>
}) {
  const [callsign, setCallsign] = useState('')
  const [role, setRole] = useState('operator')
  const [issued, setIssued] = useState<{ callsign: string; pem: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [fp, setFp] = useState<Map<string, string>>(new Map())

  const createSub = async () => {
    const cs = callsign.trim().toLowerCase()
    if (!cs) return
    if (cs.length > 32 || /\s/.test(cs)) {
      setError('Позывной: 1..32 символов без пробелов')
      return
    }
    setBusy(true)
    setError(null)
    const pem = await create(cs, role)
    setBusy(false)
    if (pem) {
      setIssued({ callsign: cs, pem })
      setCallsign('')
      onRefresh()
    } else setError('Не удалось создать абонента (возможно, не хватает прав admin)')
  }

  const download = () => {
    if (!issued) return
    const blob = new Blob([issued.pem], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${issued.callsign}.prv.pem`
    a.click()
    URL.revokeObjectURL(url)
  }

  const toggleRevoke = async (s: Subscriber) => {
    const revoke = !s.revoked
    if (revoke && !window.confirm(`Отозвать доступ абонента «${s.callsign}»? Его ключ перестанет принимать сервер.`)) return
    try {
      await onRevoke(s.callsign, revoke)
      onRefresh()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const showFp = async (s: Subscriber) => {
    if (!s.pubkey) return
    try {
      const f = await fingerprint(s.pubkey)
      setFp((prev) => new Map(prev).set(s.callsign, f))
    } catch {
      setError('Не удалось вычислить отпечаток ключа')
    }
  }

  return (
    <>
      <p className="muted">Отзыв запрещает вход по ключу и немедленно разрывает соединение.</p>
      {!isAdmin && <p className="muted">Создание и отзыв доступны только администратору. Ниже — общий список для выбора получателей.</p>}
      {isAdmin && (
        <p className="muted">
          Приватный ключ выдаётся один раз при создании и на сервере не хранится. Раздавайте{' '}
          <code>.prv.pem</code> только владельцу через доверенный канал. При утере флешки: отзовите позывной
          кнопкой «Отозвать» и создайте новый.
        </p>
      )}
      <table>
        <thead>
          <tr>
            <th>Позывной</th>
            <th>Роль</th>
            <th>Отпечаток ключа</th>
            <th>Статус</th>
            {isAdmin && <th />}
          </tr>
        </thead>
        <tbody>
          {subscribers.map((s) => (
            <tr key={s.id}>
              <td>{s.callsign}</td>
              <td>{s.role}</td>
              <td>
                <code>{fp.get(s.callsign) ?? '———'}</code>{' '}
                <button className="ghost" onClick={() => void showFp(s)} disabled={!s.pubkey}>
                  fp
                </button>
              </td>
              <td>{s.revoked ? <span className="error">ОТОЗВАН</span> : <span className="muted">активен</span>}</td>
              {isAdmin && (
                <td>
                  <button className="danger-ghost" onClick={() => void toggleRevoke(s)} disabled={s.callsign === 'admin'}>
                    {s.revoked ? 'Вернуть' : 'Отозвать'}
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      <button className="ghost" onClick={onRefresh}>
        Обновить
      </button>

      {isAdmin && (
        <>
          <h3>Регистрация нового абонента (сам админ, без CLI)</h3>
          <div className="row">
            <input placeholder="Позывной" value={callsign} onChange={(e) => setCallsign(e.target.value)} />
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="operator">operator</option>
              <option value="admin">admin</option>
            </select>
            <button onClick={() => void createSub()} disabled={busy}>
              {busy ? '…' : 'Создать ключ'}
            </button>
          </div>
        </>
      )}
      {error && <p className="error">{error}</p>}

      {issued && (
        <div className="issued">
          <p>
            Ключ для <b>{issued.callsign}</b> создан. Сохраните его на USB-флешку абонента
            (файл <code>{issued.callsign}.prv.pem</code>) — это единственный показ ключа, повторно
            скачать его нельзя. Поднесите флешку при входе — тот же ключ работает и для E2EE.
          </p>
          <button onClick={download}>Скачать приватный ключ</button>
          <textarea readOnly value={issued.pem} rows={7} />
        </div>
      )}
    </>
  )
}

function JournalTab({ isAdmin }: { isAdmin: boolean }) {
  const [entries, setEntries] = useState<JournalEntry[]>([])
  const [verified, setVerified] = useState<{ ok: boolean; head: string; badIndex: number } | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const load = async () => {
    try {
      setEntries((await fetchJournal()).entries ?? [])
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    }
  }
  useEffect(() => {
    if (isAdmin) void load()
  }, [])

  const check = async () => {
    try {
      const r = await verifyJournal()
      setVerified({ ok: r.ok, head: r.head, badIndex: r.bad_index })
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  const exportBag = () => {
    const blob = new Blob([JSON.stringify({ head: verified?.head ?? null, entries }, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'journal-bag.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <p className="muted">Tamper-evident журнал: каждый пакет связан хэшем с предыдущим (только admin).</p>
      {!isAdmin && <p className="muted">Раздел доступен только администратору.</p>}
      {isAdmin && (
        <>
          {err && <p className="error">{err}</p>}
      <div className="row">
        <button className="ghost" onClick={() => void check()}>
          Проверить целостность
        </button>
        <button className="ghost" onClick={() => void load()}>
          Обновить
        </button>
        <button className="ghost" onClick={exportBag}>
          Экспорт bag
        </button>
      </div>
      {verified &&
        (verified.ok ? (
          <p>
            Журнал целостен · {entries.length} пакетов · head <code>{verified.head.slice(0, 12)}…</code>
          </p>
        ) : (
          <p className="error">
            ПОВРЕЖДЁН: первый разрыв на позиции {verified.badIndex}. Экспортируйте bag и сверьте с резервной копией.
          </p>
        ))}
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>kind</th>
            <th>отправитель</th>
            <th>получатели</th>
            <th>время</th>
            <th>hash(prev)</th>
          </tr>
        </thead>
        <tbody>
          {entries.slice(-100).map((e, i) => (
            <tr key={e.id}>
              <td>{i}</td>
              <td>{e.kind}</td>
              <td>{e.sender}</td>
              <td>{e.recipient || 'всем'}</td>
              <td>{new Date(e.ts * 1000).toLocaleTimeString()}</td>
              <td>
                <code>{e.prev_hash.slice(0, 8)}…</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
        </>
      )}
    </>
  )
}

function ImportTab({ isAdmin }: { isAdmin: boolean }) {
  const [report, setReport] = useState<ImportReport | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [fileName, setFileName] = useState('')

  const importFile = async (file: File | undefined) => {
    if (!file) return
    setBusy(true)
    setErr(null)
    setReport(null)
    setFileName(file.name)
    try {
      const text = await file.text()
      const bag = JSON.parse(text) as { entries?: JournalEntry[] }
      if (!Array.isArray(bag.entries)) throw new Error('мешок не содержит поля "entries"')
      setReport(await importJournal(bag.entries))
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <p className="muted">
        Восстановление данных с резервного узла (sneaker-net): загрузите экспортированный journal-bag.json. Импорт
        продолжает цепочку журнала и повторно проверяет каждую подпись по локальному реестру.
      </p>
      {!isAdmin && <p className="muted">Раздел доступен только администратору.</p>}
      {isAdmin && (
        <>
          <label className="file-pick">
            {fileName || 'Выбрать journal-bag.json'}
            <input type="file" accept="application/json,.json" onChange={(e) => void importFile(e.target.files?.[0])} disabled={busy} />
          </label>
          {err && <p className="error">{err}</p>}
          {report && (
            <div className="import-report">
              {report.rejected ? (
                <p className="error">
                  Импорт отклонён на позиции {report.rejected_at}: {report.rejected_why}
                </p>
              ) : (
                <>
                  <p className="ok">
                    Импортировано пакетов: <b>{report.added_journal}</b> · дублей пропущено: {report.skipped_duplicates} ·
                    без контекста: {report.skipped_context}
                  </p>
                  <p className="muted">
                    head журнала: <code>{report.head.slice(0, 32)}…</code>
                  </p>
                </>
              )}
            </div>
          )}
        </>
      )}
    </>
  )
}

function ChatsTab({
  chats,
  subscribers,
  isAdmin,
  onCreate,
  onUpdate,
  onDelete,
  onRefresh,
}: {
  chats: Chat[]
  subscribers: Subscriber[]
  isAdmin: boolean
  onCreate: (name: string, members: string[]) => Promise<void>
  onUpdate: (id: string, name: string, members: string[]) => Promise<void>
  onDelete: (id: string) => Promise<void>
  onRefresh: () => void
}) {
  const [name, setName] = useState('')
  const [pick, setPick] = useState<string[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<Chat | null>(null)
  const [editName, setEditName] = useState('')
  const [editPick, setEditPick] = useState<string[]>([])

  if (!isAdmin) {
    return (
      <>
        <p className="muted">Именованные чаты создаёт оператор (admin). Вы видите чаты, куда вас добавили:</p>
        <ul>
          {chats.map((c) => (
            <li key={c.id}>
              <b>{c.name}</b> · {c.members.join(', ')}
            </li>
          ))}
        </ul>
        {chats.length === 0 && <p className="muted">Чатов пока нет.</p>}
        <button className="ghost" onClick={onRefresh}>
          Обновить
        </button>
      </>
    )
  }

  const toggle = (list: string[], v: string, set: (x: string[]) => void) => {
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v])
  }

  const doCreate = async () => {
    if (!name.trim() || pick.length === 0) {
      setErr('Укажите название и выберите хотя бы одного участника')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      await onCreate(name.trim(), pick)
      setName('')
      setPick([])
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const startEdit = (c: Chat) => {
    setEditing(c)
    setEditName(c.name)
    setEditPick(c.members)
  }

  const doSaveEdit = async () => {
    if (!editing) return
    if (!editName.trim() || editPick.length === 0) {
      setErr('Название и участники обязательны')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      await onUpdate(editing.id, editName.trim(), editPick)
      setEditing(null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const doDelete = async (c: Chat) => {
    if (!window.confirm(`Удалить чат «${c.name}»? Переписка останется в журнале для аудита.`)) return
    setBusy(true)
    setErr(null)
    try {
      await onDelete(c.id)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <p className="muted">
        Именованный чат — общий канал с названием и фиксированным составом. Создаёт только admin, пишут участники.
        Сообщения шифруются E2EE для участников (сервер видит только маршрутизацию <code>chat:id</code>).
      </p>
      <table>
        <thead>
          <tr>
            <th>Название</th>
            <th>Участники</th>
            <th>Создал</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {chats.map((c) => (
            <tr key={c.id}>
              <td>
                <b>{c.name}</b>
                <br />
                <code className="muted">{c.id.slice(0, 8)}…</code>
              </td>
              <td>{c.members.join(', ')}</td>
              <td className="muted">{c.creator}</td>
              <td>
                <div className="row">
                  <button className="ghost" onClick={() => startEdit(c)} disabled={busy}>
                    Изменить
                  </button>
                  <button className="danger-ghost" onClick={() => void doDelete(c)} disabled={busy}>
                    Удалить
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {chats.length === 0 && <p className="muted">Чатов пока нет — создайте первый ниже.</p>}
      <button className="ghost" onClick={onRefresh}>
        Обновить
      </button>

      <h3>Новый чат</h3>
      <div className="row">
        <input placeholder="Название чата (напр. Штаб)" value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="group-pick">
        {subscribers
          .filter((s) => !s.revoked)
          .map((s) => (
            <label key={s.callsign} className="row">
              <input type="checkbox" checked={pick.includes(s.callsign)} onChange={() => toggle(pick, s.callsign, setPick)} />
              {s.callsign} <span className="muted">({s.role})</span>
            </label>
          ))}
      </div>
      <div className="row">
        <button onClick={() => void doCreate()} disabled={busy}>
          {busy ? '…' : 'Создать чат'}
        </button>
      </div>
      {err && <p className="error">{err}</p>}

      {editing && (
        <div className="marker-form">
          <h3>Изменить чат</h3>
          <input placeholder="Название" value={editName} onChange={(e) => setEditName(e.target.value)} />
          <div className="group-pick">
            {subscribers
              .filter((s) => !s.revoked)
              .map((s) => (
                <label key={s.callsign} className="row">
                  <input
                    type="checkbox"
                    checked={editPick.includes(s.callsign)}
                    onChange={() => toggle(editPick, s.callsign, setEditPick)}
                  />
                  {s.callsign}
                </label>
              ))}
          </div>
          <div className="row">
            <button onClick={() => void doSaveEdit()} disabled={busy}>
              Сохранить
            </button>
            <button className="ghost" onClick={() => setEditing(null)}>
              Отмена
            </button>
          </div>
        </div>
      )}
    </>
  )
}

function MapsTab({ isAdmin }: { isAdmin: boolean }) {
  const [status, setStatus] = useState<TilesStatus | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [z, setZ] = useState(6)
  const [x, setX] = useState(0)
  const [y, setY] = useState(0)
  const [src, setSrc] = useState<TileSource>('osm')
  const [report, setReport] = useState<{ added: number; skipped: number } | null>(null)
  // server-side fetch (node downloads while it has internet, serves offline)
  const [fSrc, setFSrc] = useState<TileSource>('osm')
  const [fLat, setFLat] = useState(55.75)
  const [fLon, setFLon] = useState(37.62)
  const [fZmin, setFZmin] = useState(0)
  const [fZmax, setFZmax] = useState(12)
  const [fSpan, setFSpan] = useState(0.5)
  const [fetchSt, setFetchSt] = useState<TilesFetchStatus | null>(null)

  const load = async () => {
    try {
      setStatus(await fetchTilesStatus())
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    }
  }
  const loadFetch = async () => {
    try {
      setFetchSt(await fetchTilesFetchStatus())
    } catch {
      /* ignore transient */
    }
  }
  useEffect(() => {
    if (isAdmin) {
      void load()
      void loadFetch()
    }
  }, [])
  useEffect(() => {
    if (fetchSt?.state !== 'running') return
    const t = setInterval(() => void loadFetch(), 2000)
    return () => clearInterval(t)
  }, [fetchSt?.state])

  if (!isAdmin) return <p className="muted">Загрузка карт доступна только оператору (admin).</p>

  const putSingle = async (file: File | undefined) => {
    if (!file) return
    if (!file.type.includes('png') && !file.name.toLowerCase().endsWith('.png')) {
      setErr('Нужен PNG-файл тайла')
      return
    }
    setBusy(true)
    setErr(null)
    try {
      await uploadTile(z, x, y, file, src)
      await load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const putBag = async (file: File | undefined) => {
    if (!file) return
    setBusy(true)
    setErr(null)
    setReport(null)
    try {
      setReport(await uploadTilesBag(file, src))
      await load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const doFetch = async () => {
    setBusy(true)
    setErr(null)
    try {
      await startTilesFetch({ source: fSrc, lat: fLat, lon: fLon, zmin: fZmin, zmax: fZmax, span: fSpan })
      await loadFetch()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const doClear = async () => {
    if (!window.confirm('Удалить все загруженные тайлы? Встроенная карта останется.')) return
    setBusy(true)
    try {
      await clearTiles()
      await load()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <p className="muted">
        Офлайн-карта: встроенные тайлы идут в бинарнике. Два слоя — схема (OSM) и спутник (Esri):
        <code>/tiles/osm|sat/{'{z}/{x}/{y}'}.png</code>. Загруженные админом PNG-тайлы (по одному, ZIP-архивом или
        докачкой с сервера ниже) перекрывают встроенные и сразу видны всем. Обновите страницу карты после загрузки.
      </p>
      {err && <p className="error">{err}</p>}
      <div className="row">
        <button className="ghost" onClick={() => void load()} disabled={busy}>
          Обновить статус
        </button>
        <button className="danger-ghost" onClick={() => void doClear()} disabled={busy || !status?.custom_tiles}>
          Очистить загруженные
        </button>
      </div>
      {status && (
        <p>
          Загружено тайлов: <b>{status.custom_tiles}</b> (схема: {status.by_source?.osm ?? '—'} · спутник:{' '}
          {status.by_source?.sat ?? '—'}) · объём: <b>{(status.custom_bytes / 1024).toFixed(1)} KiB</b>
        </p>
      )}
      <h3>Скачать область с сервера</h3>
      <p className="muted">
        Пока у узла есть интернет — сервер сам скачает тайлы области (схема OSM или спутник Esri) и будет раздавать
        их всем офлайн. Лимиты: zoom 0..16, span 0.05..5°, не более ~20 тыс. файлов за раз.
      </p>
      <div className="row">
        <label>
          Источник{' '}
          <select value={fSrc} onChange={(e) => setFSrc(e.target.value as TileSource)}>
            <option value="osm">Схема (OSM)</option>
            <option value="sat">Спутник (Esri)</option>
          </select>
        </label>
        <label>
          lat <input type="number" step={0.01} value={fLat} onChange={(e) => setFLat(Number(e.target.value))} />
        </label>
        <label>
          lon <input type="number" step={0.01} value={fLon} onChange={(e) => setFLon(Number(e.target.value))} />
        </label>
      </div>
      <div className="row">
        <label>
          zmin{' '}
          <input type="number" min={0} max={16} value={fZmin} onChange={(e) => setFZmin(Number(e.target.value))} />
        </label>
        <label>
          zmax{' '}
          <input type="number" min={0} max={16} value={fZmax} onChange={(e) => setFZmax(Number(e.target.value))} />
        </label>
        <label>
          span° <input type="number" step={0.1} value={fSpan} onChange={(e) => setFSpan(Number(e.target.value))} />
        </label>
        <button onClick={() => void doFetch()} disabled={busy || fetchSt?.state === 'running'}>
          Скачать
        </button>
      </div>
      {fetchSt && fetchSt.state !== 'idle' && (
        <p className={fetchSt.state === 'error' ? 'error' : undefined}>
          {fetchSt.state === 'running' && (
            <>
              Скачивание ({fetchSt.source}): <b>{fetchSt.done}</b> / {fetchSt.total}
              <button className="ghost" onClick={() => void loadFetch()} style={{ marginLeft: 8 }}>
                Обновить
              </button>
            </>
          )}
          {fetchSt.state === 'done' && (
            <>
              Готово ({fetchSt.source}): <b>{fetchSt.done}</b> / {fetchSt.total}.{' '}
              <button className="ghost" onClick={() => void load()}>
                Обновить статус
              </button>
            </>
          )}
          {fetchSt.state === 'error' && (
            <>
              Ошибка ({fetchSt.source}): {fetchSt.error} — скачано {fetchSt.done} / {fetchSt.total}
            </>
          )}
        </p>
      )}
      <h3>Один тайл</h3>
      <div className="row">
        <label>
          слой{' '}
          <select value={src} onChange={(e) => setSrc(e.target.value as TileSource)}>
            <option value="osm">Схема</option>
            <option value="sat">Спутник</option>
          </select>
        </label>
        <label>
          z <input type="number" min={0} max={18} value={z} onChange={(e) => setZ(Number(e.target.value))} style={{ width: 64 }} />
        </label>
        <label>
          x <input type="number" min={0} value={x} onChange={(e) => setX(Number(e.target.value))} style={{ width: 80 }} />
        </label>
        <label>
          y <input type="number" min={0} value={y} onChange={(e) => setY(Number(e.target.value))} style={{ width: 80 }} />
        </label>
        <label className="file-pick">
          Выбрать PNG
          <input type="file" accept="image/png,.png" onChange={(e) => void putSingle(e.target.files?.[0])} disabled={busy} />
        </label>
      </div>
      <h3>ZIP-архив тайлов</h3>
      <p className="muted">
        ZIP с файлами <code>z/x/y.png</code> (как в <code>scripts/fetch_tiles.sh</code> + zip) или с префиксом слоя{' '}
        <code>osm|sat/z/x/y.png</code>. Лимит ~48 МБ запроса, PNG до 512 KiB, z 0..18.
      </p>
      <label className="file-pick">
        Выбрать tiles.zip
        <input type="file" accept=".zip,application/zip" onChange={(e) => void putBag(e.target.files?.[0])} disabled={busy} />
      </label>
      {report && (
        <p className="ok">
          Добавлено: <b>{report.added}</b> · пропущено: {report.skipped}
        </p>
      )}
    </>
  )
}