import { useRef, useState } from 'react'
import { loginFromPem } from '../crypto/signing'
import { fingerprintOfPrivate } from '../crypto/e2ee'

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
    const ok = await loginFromPem(pem, callsign.trim().toLowerCase())
    setBusy(false)
    if (!ok) {
      setError('Не удалось импортировать ключ (ожидается ECDSA P-256 PKCS#8)')
      return
    }
    onLogin(callsign.trim().toLowerCase())
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