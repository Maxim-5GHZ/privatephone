import { useRef, useState } from 'react'
import { loginFromPem } from '../crypto/signing'

export function Login({ onLogin }: { onLogin: (callsign: string) => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [callsign, setCallsign] = useState('')
  const [pem, setPem] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const pick = async (f: File | null) => {
    if (!f) return
    setPem(await f.text())
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
      />
      <input
        ref={fileRef}
        type="file"
        accept=".pem,.key,.prv,text/plain"
        onChange={(e) => void pick(e.target.files?.[0] ?? null)}
      />
      <button onClick={() => void submit()} disabled={busy}>
        {busy ? 'Проверка…' : 'Войти по ключу (флешка)'}
      </button>
      {error && <p className="error">{error}</p>}
      <p className="hint">
        Файл приватного ключа лежит на вашей USB-флешке и выдаётся связисom при регистрации.
      </p>
    </div>
  )
}