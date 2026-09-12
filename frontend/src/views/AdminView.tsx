import { useEffect, useState } from 'react'
import { Subscriber } from '../types'
import { fetchJournal, fetchAdminStats, importJournal, AdminStats, ImportReport, JournalEntry, verifyJournal } from '../api/client'
import { fingerprint, isE2eeArmed } from '../crypto/e2ee'

interface Props {
  subscribers: Subscriber[]
  onCreate: (callsign: string, role: string) => Promise<string | null> // returns private pem or null
  onRefresh: () => void
  onRevoke: (callsign: string, revoke: boolean) => Promise<void>
}

type Section = 'subs' | 'journal' | 'import'

export function AdminView({ subscribers, onCreate, onRefresh, onRevoke }: Props) {
  const [section, setSection] = useState<Section>('subs')
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [statsErr, setStatsErr] = useState<string | null>(null)

  const loadStats = async () => {
    try {
      setStats(await fetchAdminStats())
      setStatsErr(null)
    } catch (e) {
      setStatsErr((e as Error).message)
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
        <button className={section === 'journal' ? 'active' : 'ghost'} onClick={() => setSection('journal')}>
          Журнал
        </button>
        <button className={section === 'import' ? 'active' : 'ghost'} onClick={() => setSection('import')}>
          Импорт с УСБ
        </button>
      </div>

      {section === 'subs' && <SubscribersTab subscribers={subscribers} onRefresh={onRefresh} onRevoke={onRevoke} create={(c, r) => onCreate(c, r)} />}
      {section === 'journal' && <JournalTab />}
      {section === 'import' && <ImportTab />}
    </div>
  )
}

function SubscribersTab({
  subscribers,
  onRefresh,
  onRevoke,
  create,
}: {
  subscribers: Subscriber[]
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
    if (!callsign.trim()) return
    setBusy(true)
    setError(null)
    const pem = await create(callsign.trim().toLowerCase(), role)
    setBusy(false)
    if (pem) setIssued({ callsign: callsign.trim().toLowerCase(), pem })
    else setError('Не удалось создать абонента (возможно, не хватает прав admin)')
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
      <table>
        <thead>
          <tr>
            <th>Позывной</th>
            <th>Роль</th>
            <th>Отпечаток ключа</th>
            <th>Статус</th>
            <th />
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
              <td>
                <button className="danger-ghost" onClick={() => void toggleRevoke(s)} disabled={s.callsign === 'admin'}>
                  {s.revoked ? 'Вернуть' : 'Отозвать'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="ghost" onClick={onRefresh}>
        Обновить
      </button>

      <h3>Регистрация нового абонента (связист)</h3>
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
      {error && <p className="error">{error}</p>}

      {issued && (
        <div className="issued">
          <p>
            Ключ для <b>{issued.callsign}</b> готов. Сохраните его на USB-флешку абонента (файл{' '}
            <code>{issued.callsign}.prv.pem</code>). Поднесите флешку при входе — тот же ключ работает и для E2EE.
          </p>
          <button onClick={download}>Скачать приватный ключ</button>
          <textarea readOnly value={issued.pem} rows={7} />
        </div>
      )}
    </>
  )
}

function JournalTab() {
  const [entries, setEntries] = useState<JournalEntry[]>([])
  const [verified, setVerified] = useState<{ ok: boolean; head: string; badIndex: number } | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const load = async () => {
    try {
      setEntries((await fetchJournal()).entries)
      setErr(null)
    } catch (e) {
      setErr((e as Error).message)
    }
  }
  useEffect(() => {
    void load()
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
  )
}

function ImportTab() {
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
  )
}