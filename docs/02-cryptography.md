# 02 — Криптография

Проект использует **стандартную, проверенную криптографию** (NIST-кривые,
AES-GCM, SHA-256, HKDF, ECDSA) без собственных «алгоритмов». Нестандартная тут
**инженерия**: как именно компонуются примитивы, где живут ключи, как они
затираются и как связываются друг с другом.

Используемые примитивы и их место:

| Примитив | Назначение | Где |
|---|---|---|
| ECDSA P-256 (SHA-256) | подпись каждого пакета | сервер `sign.go`, сервер канон; браузер WebCrypto `signing.ts` |
| ECDH P-256 | общие ключи для E2EE-конвертов | браузер `e2ee.ts` |
| AES-256-GCM | шифрование vault, тела конверта, кадров sframe | сервер `encrypt.go`; браузер |
| HKDF-SHA-256 | производные ключи (конверт, sframe) | браузер `e2ee.ts`, `sframe.ts` |
| SHA-256 | мастер-ключ из половин, ID пакета, chain-хэши, отпечатки | сервер `master.go`, `store.go`, `e2ee.ts` |

## 1. Мастер-ключ базы из двух половин

### Идея
База шифруется ключом, который **не хранится целиком нигде**. Узел владеет
половиной-A (`data/pp.local` на диске машины), половиной-B — USB-флешка
оператора (`pp.key`). Расшифровать базу можно только имея обе части: потеря
любой из них делает базу неоткрываемой.

### Формат файла-половины (`server/internal/crypto/master.go:17-47`)
```
Байты: 0..7     магия		       "PPHALF\x00"
       8        версия формата    = 1
       9..24    nodeID            16 случайных байт, ОДИНАКОВ в обеих половинах
       25       длина имени узла  (0..60)
       26..     короткое имя      («ТАНЖЕР»), не секретно
       ..       сырые 32 байта    материал половины
```
nodeID и имя узла — не секрет, они лишь **связывают** половины с узлом и
позволяют отвергать чужие флешки *до* попытки расшифровки.

### Сборка мастер-ключа
```
masterKey = SHA-256( pp.local_raw ‖ pp.key_raw )     master.go:194-197
```
`KeyFromHalves` (master.go:179) сначала сверяет `NodeID` обеих половин — при
несовпадении ошибка «половины разных узлов». Повторная сверка выполняется и
при выборе флешки: `resolveKeySource`
при выборе флешки: из скана `scanSticks()` к предложению идут ТОЛЬКО носители
того же NodeID (usb_common.go:226-259); носители чужих узлов перечисляются как
предупреждения и никогда не предлагаются.

### Жизнь ключа в памяти (mlock/munlock)
- `MasterKey` держит ключ в буфере, закреплённом в RAM: `mlock` на
  Linux/macOS (`memlock_unix.go:8-15`), `VirtualLock` на Windows
  (`memlock_windows.go:24-70`), заглушка на других (`memlock_other.go`).
- Назначение mlock: ключ **не вытесняется на диск/в swap** операционной
  системой.
- `Destroy()` → зануление (`clear`) + `munlock` + освобождение (master.go:286-316).
- Промежуточные буферы (половины, байт-копии) зануляются сразу после
  использования (`clear`), э.г. master.go:184-189.

### Watchdog на извлечение флешки (`MasterKey.Watch`, master.go:296-308)
- `Watch(interval, onLoss)`: тикер `Present()` = `os.Stat(path)`.
- Если носитель исчез → `Destroy()` + колбэк.
- В `cmdRun`: `mk.Watch(time.Second, …)` → `st.Close` + `os.Exit(1)` (main.go:736-744).
  Итого: вынул флешку → ~1 секунда → ключ затёрт, узел погашен.

### Резервный режим (single-key, `-key PATH`)
- Полный ключ одним файлом 32 байта: `CreateMasterKey`/`LoadMasterKey`
  (master.go:74-101). Используется для развёртывания-резерва (`-rescue-out`
  пишет его в сейф, main.go:166-171) и в dev-режиме (см. `04-deployment`).

## 2. Шифрование базы vault.db

`server/internal/db/encrypt.go`

```
vault.db = [ 12-байтный случайный GCM-nonce ‖ AES-256-GCM ciphertext ]
```

- `seal` (encrypt.go:19-45): AES-256-GCM с 32-байтным ключом (master), случайный
  nonce 12 Б, **AAD отсутствует** (nil). Запись атомарная: `.part` 0600 → rename.
- `unseal` (encrypt.go:48-73): `Open`-операция GCM, при неверном ключе/подмене —
  ошибка «vault decrypt failed (wrong master key, tampering, or corruption)».
  Файл отсутствует → пусто (первый запуск).
- **GCM authenticates**: подмена любых байт блоба (или ключа) даёт ошибку, а не
  мусорные данные. Это механизм tamper-evident'ности БД на уровне файла.

Живой рабочий SQLite **не на диске**: распечатывается в RAM-файл
`/dev/shm/pp-vault/vault.raw-<pid>-<rand>` на Linux (иначе в data/),
`db.go:40-51,63-92`. При персисте:
```
VACUUM INTO '<tmp>.snap'  →  seal(...)  →  перезапись vault.db      db.go:313-345
```
Интервал: `PersistentEvery(ctx, 5s)` (`-persist`, main.go:606,697); финальный
снапшот при `Close`. Плюс `Store.mu` защищает от параллельного снапшота.

## 3. Подписи пакетов (ECDSA P-256)

### Ключи абонентов
- Генерация: `ca.Create` → кривая P-256, `crypto.NewID()` = 8 случайных байт →
  16 hex-символов ID (keys.go:14-16, 71-78).
- Приватный: **PKCS#8** PEM (`"PRIVATE KEY"`, keys.go:20-26) — совместим с
  WebCrypto `importKey('pkcs8', …)`.
- Публичный: **SPKI** PEM (`"PUBLIC KEY"`, keys.go:29-35) — хранится в реестре
  сервера.
- Приватный отдаётся оператору ОДИН раз (на флешку абонента), на сервере не
  хранится. Публичный — всем клиентам через `GET /api/v1/subscribers`.

### Канонический формат подписи (`sign.go:17-35`)
Подписывается не JSON (порядок полей может переставиться), а каноническая
строка, байт-в-байт одинаковая в Go и JS:
```
v=1\n
kind=<kind>\n
sender=<sender>\n
ts=<ts>\n
nonce=<nonce>\n
<исходные байты тела data, без переформатирования>
```
Клиент строит ровно ту же строку и подписывает WebCrypto
`{name:'ECDSA', hash:'SHA-256'}` (signing.ts:84-109). Подпись — `base64(ASN.1
(r‖s))`. Проверка — `ecdsa.VerifyASN1` (sign.go:47-55).

### Верификатор `protocol.Verifier.Verify` (protocol.go:73-95), порядок важен
1. Поля `Frame` присутствуют и не пусты.
2. Lookup реестра: неизвестный → `ErrUnknownSender`; отозванный → `ErrRevoked`
   (main.go:714-717).
3. Проверка подписи по канону → `ErrBadSignature`.
4. **(После подписи!)** replay-guard → `ErrReplay`; если включена калибровка
   часов — сначала обучается по пакетам админа, затем `AdjustedNow`.

Причины порядка: (а) подпись проверяется до nonce-кэша — мусорный трафик не
засоряет кэш; (б) только **проверенные** admin-пакеты влияют на оценку часов —
атакующий не может сдвинуть часы узла.

### Replay-guard (`sign.go:57-104`)
- `NewReplayGuard(max=10000, window=10m)` — кэш nonce (последних 10 000) и окно
  свежести.
- `CheckAt(nowSec, nonce, ts)`: `ts < now-window` или `ts > now+window` → отказ
  (анти-«заправка» и анти-future); повторный nonce → отказ (анти-replay).
- При переполнении кэша вычищаются записи старше окна.

### Калибровка часов (`clock.go`)
- Офлайн-часы абонентских устройств дрейфуют. Сервер позволяет `-clock-calibrate`:
  `Observe(now, ts)` по **admin**-пакетам: `delta = ts - now`, клиппинг ±30 мин
  (`MaxClockCorrection`), **EMA** `offset += (delta-offset)/4` (α=0.25).
- `AdjustedNow()` прибавляет смещение перед replay-guard (protocol.go:89-91).
  Всё вместе смягчает ложные отказы по «кривым часам» без ослабления защиты.

### Отзыв ключа (CRL)
- `subscribers.revoked` в БД (store.go:156-179); живой отозванный не проходит
  `Verify` (ErrRevoked), исключается из доставки (relay.go:100-102), его
  WS-соединение принудительно рвётся (`Kick`, hub.go:185-191); in-memory
  `hub.revoked` — defence-in-depth (hub.go:43-58). «Отзыв» — само журналируется
  (`@system`).

## 4. E2EE содержимого (фронтенд)

Это **не X3DH и не double-ratchet** — упрощённая, но forward-secret схема:
конверт с **эфемерным ECDH-ключом на каждое сообщение** и индивидуальной
обёрткой ключа под каждого получателя.

### Построение конверта (`e2ee.ts:156-182`, encrypt)
```
msgKey = rand(32)                                  — ключ сообщения
iv0    = rand(12)
c      = AES-256-GCM(msgKey, iv0, UTF8(plaintext))  — тело
eph    = generateKey(ECDH P-256)                    — СВЕЖИЙ ключ на сообщение
epub   = exportKey(raw, eph)                        — точка P-256, 65 байт

для каждого получателя R:
  shared = ECDH(eph_priv, R_static_pub)             — у R: ECDH(R_static_priv, epub)
  salt   = rand(32)                                 — публичный, рандомизирует HKDF
  kek    = HKDF-SHA-256(shared, salt, info="pp-e2ee/v2")  → 32 байта
  iv     = rand(12)
  ek     = AES-256-GCM(kek, iv, msgKey)             — обёртка msgKey под R
  запись {to: callsign, salt, iv, ek} (base64)

итог:  { v: 2, alg: 'A256GCM', epub, iv: b64(iv0), c: b64(c), k: [records…] }
```
- Расшифровать могут **отправитель и все адресаты** (каждый — свою запись `k[]`;
  чужая — `continue`, e2ee.ts:201-214).
- **Forward secrecy**: эфемерный приватный ключ уничтожается сразу; компрометация
  статического (подписывающего) ключа в будущем не вскрывает прошлые конверты.
- **Зачем salt**: идентичный shared между парами давал бы одинаковую kek;
  случайный salt даёт уникальность HKDF-выхода даже при одной паре ключей
  (и разрывает корреляцию общих ключей между сообщениями).
- **V1 (legacy)**: `shared = ECDH(статические пары)`, `info="pp-e2ee/v1"` — без
  epub, без forward-secret; decrypt понимает оба (e2ee.ts:188-228). Версия берётся
  из конверта.
- Узел видит конверт целиком (хранит его opaque в `packets.payload`) и меняет
  отображаемые поля на `"enc"` (lat=0, type='enc' и т.п.) — см. `03-protocol` §6.

### Кэш расшифровок (`useDecrypt.ts`)
- `cache = Map<id, Promise<string|null>>`: строка расшифровывается **один раз за
  сессию**; ключ кэша — контент-адресация по точному ciphertext
  `encId(kind, sender, text)` (content.ts:20-23). Новый конверт на ту же метку →
  новый ID → свежая расшифровка.
- `clearDecryptCache()` при logout — следующий оператор не увидит чужой
  plaintext (добавлено в Task 0).

### Отпечаток (fingerprint)
`SHA-256(raw SPKI-точка)` → 8 верхних hex (e2ee.ts:101-111). Показывается при
входе — контроль «правильный ли ключ на флешке».

## 5. Защита WebRTC-сигналинга (`signal.ts`)

SDP (session description), ICE-кандидаты и SFrame-груп-ключ запечатываются **тем
же E2EE-конвертом**: `sealSignal(recipients,payload) = encrypt(...)` (signal.ts:39-42).
Узел видит у сигнального фрейма только маршрутизацию (`to`/`n`/`talks`), а
`sdp/candidate/sframe` — как opaque `enc`. Если абонент не знает твоих ключей,
этот конверт ему не прочитать. `mkRecipients(me, pubOf, targets)` собирает
множество «я + все цели» (signal.ts:25-36).

Сюда же уходит **SFrame-ключ**: в `call_invite` (webRTC.ts:90) и в `ptt_start`
(ptt.ts:84) — то есть груп-ключ медиа никогда не ходит открытым.

## 6. SFrame — покадровое шифрование медиа

`frontend/src/media/sframe.ts` + `sframe.worker.ts`. Слой поверх браузерного
DTLS-SRTP (защищает транспорт) — E2EE между браузерами; без груп-ключа узел или
скомпрометированный абонент не прочитают и не инжектируют аудио.

### Формат кадра v1
```
[ 0x80 | keyId(7 бит) ] [ counter (varint base-128 BE, до 5 групп, ≤0xffffffff) ] [ AES-256-GCM тело покадрово ]
```
Заголовок/Counter — sframe.ts:92-109, decodeVarint — sframe.ts:76-89.

### Производные ключи (не ratchet-цепочка)
```
derive(base, keyId, counter):
  salt = 5 байт [ keyId (1) ‖ counter u32 BE (4) ]
  HKDF-SHA-256(base, salt, info='pp-sframe/v1') → 44 байта = 32 (key) + 12 (iv)
```
- Каждый кадр (keyId,counter) получает **свою** пару ключ/IV: утёкший ключ
  кадра не вскрывает ни один другой кадр (sframe.ts:113-131).
- Утечка IV не страшна (GCM-надёжность). Шифрование: worker инкрементит counter на
  каждый зашифрованный кадр (sframe.worker.ts:48).

### Анти-replay в медиа
`REORDER_LIMIT=100`: принятый counter меньше `last-100` → фрейм отклоняется
(sframe.ts:161-167), допускается лишь перестановка последних 100 кадров.

### Эпохи/направления
- Звонок 1:1: каждый ставит свою эпоху, callee зеркалит keyId
  (`sframeFromShare(share, mirror=true)`, webRTC.ts:108) — направление A→B и B→A
  ключи разные (outKeyId=1, inKeyId=2, sframe.ts:32-37).
- Рация: все используют layout создателя (`mirror=false`, ptt.ts:96).

### Встраивание через encoded transforms
- `RTCRtpScriptTransform` + Worker (`sframe.worker.ts:20-68`) перехватывают
  кодированные кадры: send — encrypt, recv — decrypt (модификация `frame.data`).
- **Честный fallback**: `sframeSupported()` — нет `RTCRtpScriptTransform`/Worker →
  канал остаётся на «чистом» DTLS-SRTP, UI показывает это через
  `onLink(secure=false)` (sframe.ts:59-62; webRTC.ts:245-262; ptt.ts:286-307).
  Скрывать снижение защиты нельзя.

## 7. CA и TLS-сертификаты узла (`server/internal/crypto/cert.go`)

- **Внутренний CA** `write` в `init`: самоподписанный ECDSA P-256, 10 лет,
  `KeyUsage=CertSign|CRLSign|DigitalSignature`, `IsCA=true`, `MaxPathLen=0`
  (только leaf). `org="PrivatePhone Mesh CA"` (cert.go:80-116, main.go:226).
- **Серверный leaf**: подписывается CA, ECDSA P-256, `NotBefore=now-1h`
  (бэкрейд на часовой сдвиг), `NotAfter=now+10y`, EKU `ServerAuth`,
  `DNSNames=["localhost"]`; IP SAN — из `-ips`, fallback `127.0.0.1`, всегда
  `::1` (cert.go:122-201). В визарде IP автоопределяется `firstLANIPv4()`
  (usb_common.go:309-336).
- Один корень `ca.crt` на весь меш: импортируется один раз на всех абонентских
  устройствах (README §развёртывание, `scripts/install_ca.sh`) — без этого
  браузер ругается на самоподписанный серт и не даёт WebRTC (secure context).
- Подача: `srv.WithTLS(data/tls.crt, data/tls.key)` → `ListenAndServeTLS`
  (server.go:31-34,69-74). Автоматическое включение TLS при первом запуске
  без флагов (main.go:625-631).

## 8. WebRTC и транспорт медиа

- `RTCPeerConnection({iceServers: []})` — только **host-кандидаты** (одна ЛВС,
  webRTC.ts:206): сознательно нет STUN/TURN, нет внешних сервисов.
- SRTP настраивается браузером по умолчанию (DTLS-SRTP), SFrame поверх (см. §6).
- `replaceTrack` для переключения «кто говорит» вместо повторного renegotiation
  (ptt.ts:109-130).
- Аудио-файлы интерфейса (звонок/тревога) — только WebAudio-потоки (audio.ts),
  к криптографии не относятся.

## 9. Проверки и границы схемы

- **Все примитивы стандартные**; «алгоритмы invented here» нет. Критичное
  место — комбинаторика: half-файлы → SHA-256 → AES-GCM vault; канон → ECDSA →
  replay-guard; ECDH+HKDF+AES-GCM конверты; SFrame-производные. Тесты
  (e2e_phase*, sign_test, master_test, journal_test, e2ee.test, sframe.test)
  проверяют каждый слой, включая «негативную» крипту (чужие ключи, подмена,
  отзыв, повтор).
- **Известные допущения**: AAD у vault-GCM = nil (целостность всё равно есть —
  AAD здесь не нужен, файл не дополняется «по контексту»); калибровка часов
  работает, только если админ отправляет пакеты; no rotation static-ключей
  абонентов — компрометация решается отзывом + новыми ключами.