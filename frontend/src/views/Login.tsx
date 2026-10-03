import { useRef, useState } from 'react'
import { loginFromPem, logout } from '../crypto/signing'
import { fingerprintOfPrivate } from '../crypto/e2ee'
import { apiGet } from '../api/client'

export function Login({ onLogin }: { onLogin: (callsign: string) => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [callsign, setCallsign] = useState('')
  const [pem, setPem] = useState('')
  const [fingerprint, setFingerprint] = useState('')
  const [dragActive, setDragActive] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const adopt = async (f: File | null) => {
    if (!f) return
    const text = await f.text()
    setPem(text)
    setError(null)
    fingerprintOfPrivate(text)
      .then((fp) => setFingerprint(fp))
      .catch(() => setFingerprint(''))
  }

  const submit = async () => {
    if (!pem || !callsign.trim()) {
      setError('Выберите ключ с USB-носителя и укажите позывной')
      return
    }
    setBusy(true)
    setError(null)
    const cs = callsign.trim().toLowerCase()
    const ok = await loginFromPem(pem, cs)
    if (!ok) {
      setBusy(false)
      setError('Не удалось импортировать ключ (ожидается ECDSA P-256 PKCS#8)')
      return
    }
    // Ключ в память встал — теперь проверяем его О СЕРВЕР: позывной должен
    // быть в реестре ЭТОГО data-каталога, иначе дальше везде будет
    // «invalid signature», а админка покажет «не админ».
    try {
      await apiGet('/api/v1/subscribers', 'list_subscribers')
    } catch (e) {
      logout()
      setBusy(false)
      setError(
        `Сервер ключ не принял: ${(e as Error).message}. Возьмите файл из data-каталога ЭТОГО узла ` +
          `(см. строку «мастер-ключ из половин» в логе сервера — admin.pem рядом с vault.db), ` +
          `позывной — admin, и обновите страницу.`,
      )
      return
    }
    setBusy(false)
    onLogin(cs)
  }

  return (
    <div className="login">
      <h1>ПАК АСК</h1>
      <p className="muted">Защищённый обмен данными. Доступ — только по ключу с USB-флешки.</p>
      <input
        placeholder="Позывной"
        value={callsign}
        onChange={(e) => setCallsign(e.target.value)}
        autoCapitalize="off"
        autoComplete="off"
      />
      <div
        className={`dropzone${dragActive ? ' drag' : ''}`}
        onDragOver={(e) => {
          e.preventDefault()
          setDragActive(true)
        }}
        onDragLeave={(e) => {
          e.preventDefault()
          setDragActive(false)
        }}
        onDrop={(e) => {
          e.preventDefault()
          setDragActive(false)
          void adopt(e.dataTransfer.files?.[0] ?? null)
        }}
        onClick={() => fileRef.current?.click()}
      >
        {pem ? 'Ключ загружен — нажмите для замены' : 'Перетащите файл ключа сюда или нажмите'}
      </div>
      {fingerprint && (
        <p className="fingerprint" title="Отпечаток ключа">
          Отпечаток: {fingerprint}
        </p>
      )}
      <input
        ref={fileRef}
        type="file"
        accept=".pem,.key,.prv,text/plain"
        onChange={(e) => void adopt(e.target.files?.[0] ?? null)}
      />
      <button onClick={() => void submit()} disabled={busy}>
        {busy ? 'Проверка…' : 'Войти по ключу (флешка)'}
      </button>
      {error && <p className="error">{error}</p>}
      <p className="hint">
        Файл приватного ключа лежит на вашей USB-флешке и выдаётся связисom при регистрации. Ключ
        живёт только в памяти страницы и не сохраняется.
      </p>
    </div>
  )
}