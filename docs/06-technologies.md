# 06 — Технологии и почему они выбраны

Стек, используемые библиотеки, обоснование выбора, альтернативы и границы.

## 1. Карта стека

```
┌─────────────── 1 СТАТИЧЕСКИЙ БИНАРЬ (Go) ───────────────┐
│ Go (stdlib: crypto/ecdsa, aes, cipher, x509)            │
│ + modernc.org/sqlite (чистый Go-SQLite, без CGO)        │
│ + coder/websocket (WS-транспорт)                        │
│ + x/crypto (HKDF в e2e-тестах), x/sys (memlock Win)     │
│ + go:embed  → server/internal/web/{dist,tiles}          │
└─────────────────────────────────────────────────────────┘
                 │ REST/WS/TLS
┌─────────────── БРАУЗЕР (React SPA) ─────────────────────┐
│ React 19 + react-dom (createRoot)                       │
│ Vite 6 + TypeScript 5.7 (build/dev)                     │
│ OpenLayers (карта, офлайн-тайлы osm/sat)                  │
│ WebCrypto (ECDSA-подпись, ECDH/HKDF/AES-GCM E2EE)       │
│ WebRTC (RTCPeerConnection) + RTCRtpScriptTransform+SFrame│
│ Vitest 4 (unit-тесты крипты/media)                      │
└─────────────────────────────────────────────────────────┘
```

## 2. Сервер: Go

- **Причина**: один статический бинарь без зависимостей на хосте — центральное
  требование (офлайн-поле, никаких Docker/nginx/Node на узле). Go с `CGO_ENABLED=0`
  даёт это из коробки.
- **Транспорт**: стандартная библиотека `net/http` (HTTP/1.1), TLS через
  `crypto/tls` + `x509` (генерация CA/лист-сертов), `mux`/handlers вручную
  (`api/server.go`), SPA-раздача через `go:embed`.
- **Крипто**: `crypto/ecdsa` (P-256), `crypto/aes` + `cipher.NewGCM`,
  `crypto/sha256`, `crypto/rand` — всё из стандартной библиотеки (только
  проверенные примитивы; своих «алгоритмов» нет — см. `02-cryptography`).
- **ASN.1 подписи**: `ecdsa.SignASN1/VerifyASN1` совместимы с WebCrypto
  ECDSA-SHA-256 (sign.go:37-55) — межязыковая совместимость без кастомизации.

### Зависимости Go (server/go.mod)
| Модуль | Зачем |
|---|---|
| `coder/websocket` v1.8.15 | WebSocket-хаб: контекстный API (нет глобальных «conn.WriteMessage» из горутин — безопасно), поддержка ping/pong, backpressure через каналы |
| `modernc.org/sqlite` v1.58.0 | настоящий SQLite в чистом Go (трансляция C→Go), работает с `CGO_ENABLED=0` — кросс-сборка без toolchain C |
| `x/crypto` | HKDF-SHA-256 (в e2e-тестах сверки E2EE с фронтендом) |
| `x/sys` | `VirtualLock` на Windows для mlock-аналога мастер-ключа |

**Почему не**: `bbolt` (нет SQL/индексов/`VACUUM`-снапшота), `gorilla/websocket`
(устаревший style API), `mattn/go-sqlite3`/CGO (поломал бы статическую сборку).

## 3. База: зашифрованный SQLite

- **SQLite** (а не отдельный процесс БД): встраиваемая, надёжная, файл-снапшот
  (`VACUUM INTO`) идеально ложится на «шифруем весь файл атомарно».
- Шифрование — на уровне **файла**: `[nonce(12)|AES-256-GCM ciphertext]`
  (`encrypt.go`). Вся БД (`subscribers/markers/messages/packets/alerts/zones`)
  в одном блобе. Рабочая копия в `RAM` (`/dev/shm`), на диск пишется только
  зашифрованный снапшот каждые 5 c.
- Атомарность: `.part` + `rename`; GCM-authenticated (подмена файла → ошибка).
- Миграции — колоночные `ensureColumn`/бэкфиллы (db.go:198-311), идемпотентные.

### Объекты (store.go)
`Subscriber{callsign,role,pubkey,revoked}`, `Marker{lat,lon,type,desc,n}`,
`Alert{type,text,lat,lon,acks,cleared}`, `Zone{name,color,points}`,
`Message{recipient,body,n}`, `Packet/JournalEntry{..,prev_hash,delivered}`.

## 4. WebSocket-меш

`coder/websocket` + собственный хаб (`ws/hub.go`):
- **модель доставки** — канал на клиента (`send chan []byte`, буфер 256) →
  единственный `writePump`: исключает гонки записи в сокет.
- **backpressure**: неблокирующий `tryEnqueue`; полный буфер → клиент закрыт
  (защита от медленного потребителя, hub_test.go:278-316). Это «правильный»
  WS-паттерн для broadcast-меша.
- **transport-подпись**: каждый фрейм — подписанный ECDSA-пакет (`protocol.Frame`)
  и проверяется через `Verifier`; WS — не «канал речи посредника».
- **store-and-forward**: snapshot+backlog после `hello`; ack-протокол.

## 5. Криптография на клиенте: WebCrypto, не libsodium

- Всё — системный WebCrypto (ECDSA P-256, ECDH P-256, AES-GCM, HKDF, SHA-256).
  Хранить приватные ключи в JS — плохо; WebCrypto использует их
  **non-extractable** (`extractable:false`, `keyUsages` — только нужные): даже
  память страницы не отдаст ключ через `exportKey`.
- **Почему не libsodium/Web Crypto polyfill**: одной копии WebCrypto достаточно;
  соблюдается требование «Zero-зависимостей» леса.
- **Почему не ГОСТ/«военная» крипта**: цель — стандартная брутфорс-стойкая
  крипта, поддающаяся аудиту и совместимая с любым браузером.

### Ключевые модули клиентской крипты
`signing.ts` (подпись+канон), `e2ee.ts` (конверты, «v1 legacy»), `signal.ts`
(шифрование SDP/ICE/ключ), `useDecrypt.ts` (кэш расшифровок), `content.ts`
(адресация/дедуп), `sframe.ts`+`sframe.worker.ts` (медиа-шифрование).

## 6. Медиа: WebRTC + SFrame

- **RTCPeerConnection**: P2P, host-кандидаты (без STUN/TURN — нет внешних
  сервисов); DTLS-SRTP даёт браузер по умолчанию.
- **SFrame** поверх: покадровое E2EE-шифрование кодированных RTP-фреймов через
  `RTCRtpScriptTransform` (encoded insertable streams) — WebRTC Encoded Transform
  API (актуальный стандарт; реализован в Chrome/Firefox). Ключ группы — один раз
  в зашифрованном сигнал-конверте.
- **Честный fallback**: нет поддержки encoded transforms → канал только
  DTLS-SRTP, UI в явном виде говорит «не E2EE» (sframe.ts:59-62).
- **replaceTrack** вместо renegotiation — дешёвое переключение «кто говорит» в
  полном-меш-рации (ptt.ts:109-130).

## 7. Фронтенд: React 19 + Vite 6 + OpenLayers

- **React 19** — стандарт UI; SPA без routing-либ (вкладки в `App.tsx`).
- **Vite 6** — сборщик и dev-сервер (:5173, proxy → :8080); быстрый, стабильный.
  Прод — статические файлы в embed, никакого Node на узле.
- **TypeScript 5.7** — типы для криптографических данных и договорных форматов (`types.ts` —
  маркеры/зоны/алерты/фреймы).
- **OpenLayers**: офлайн-карта с двумя слоями (`/tiles/osm|sat/{z}/{x}/{y}.png`),
  векторные маркеры/зоны, React-попапы через Overlay; XYZ-поток тайлов из embed +
  `data/tiles/` офлайн. Докачка области — серверным воркером (`POST
  /api/v1/admin/tiles/fetch`, см. `04-deployment`), когда у узла есть интернет.
- **Vitest 4** — юнит-тесты крипты (e2ee/signal/content/sframe) без e2e-хопов.
- **PWA**: manifest + иконка (без service worker — офлайн-кэш обеспечивают
  встроенные тайлы, а не SW; минимальный PWA-профиль).

## 8. Инструменты сборки и интеграции

| Инструмент | Роль |
|---|---|
| Makefile | оркестрация: `ui→gentiles→build→cross`, `init/run/dev`, `test/cover/vet`, `tiles` |
| `go:embed` | вшивание UI и тайлов в бинарь (`web.go:10-13`) |
| `CGO_ENABLED=0` | гарантия кросс-компиляции без C-тулчейна |
| `-trimpath -ldflags="-s -w"` | воспроизводимость и размер бинаря |
| scripts/dev.sh | dev-контур без Docker (Go :8080 + Vite :5173) |
| scripts/fetch_tiles.sh | скачивание OSM-тайлов в embed |
| scripts/install_ca.sh | импорт `ca.crt` в доверенные (Linux/macOS/Windows) |
| scripts/coverage.sh | кросс-пакетный порог Go-покрытия ≥ COVER_THRESHOLD |

## 9. Тестирование: как проверяется продукт

### Фронт (Vitest)
- `crypto/e2ee.test.ts` — roundtrip конверта v2 отправитель/адресаты, «чужой»
  не расшифрует, свежесть эфемерных ключей, tampered ciphertext/pub, legacy v1,
  fingerprint, распознавание конвертов.
- `crypto/signal.test.ts` — mkRecipients, seal/open SDP+sframe, ошибки ключей.
- `crypto/content.test.ts` — recipientList, encId-кэширование.
- `media/sframe.test.ts` — varint, заголовки, roundtrip шифрования кадров,
  отказ брака/подмены.

### Сервер (Go)
- `crypto`: sign/verify, ReplayGuard, ClockOffset, master halves lifecycle +
  Watch-срабатывание при unlink, CA/TLS-цепочка.
- `db`: roundtrip/неверный ключ/tamper, persist-no-op, store filters, журнал
  (целостность/дедуп/backfill).
- `protocol`: калибровка часов по admin-, отказ после отзыва, malformed.
- `api/e2e_phase1..6` — сквозные подписанные сценарии: CRL, тревоги/зоны,
  PTT-релей, импорт мешков, E2EE-непрозрачность сервера, pending→ack, SPA,
  ServeTLS; `e2e_routing_test` — direct/group/broadcast, только-получателю.
- `ws`: dispatch всех kinds, revoked-доставка, malformed/impostors, backpressure.
- `cmd/server/usb_*`: половины, отбрасывание чужих флешек, интерактивный выбор, визард.

`make test` = `go test ./...` + `npm test`; `make cover` — порог 80%
(`scripts/coverage.sh`).

## 10. Альтернативы, осознанно не выбранные

| Вопрос | Выбрали | Почему НЕ альтернативу |
|---|---|---|
| Транспорт аплинка | подписанный WS + REST | gRPC/QUIC — лишняя зависимость; браузеры без библиотеки не говорят |
| Подпись | ECDSA P-256 WebCrypto | X25519/Ed25519 не встроены в WebCrypto (не ECDSA/EdDSA-поддержка разная); P-256 — совместим с браузером и стандартом |
| E2EE | ECDH+HKDF+AES-GCM конверты | Signal-ratchet (X3DH/Double-Ratchet) в WebCrypto — сложный и тяжёлый; для offline-сообщений и event-репликации хватает forward-secret конвертов |
| Медиа-E2EE | SFrame (encoded transforms) | embedded DTLS-only слабее; классические E2EE-варианты DTLS в браузере недоступны |
| БД на узле | зашифрованный SQLite-снапшот | полноценный «шифрованный Postgres» — оверхед и больше attack surface |
| Публикация | embed+go:embed | отдельные артефакты (nginx + dist) нарушают «один файл» |

## 11. Границы технологического выбора

- WebCrypto → **SHA-1 не используется**, эллиптика только P-256; лимиты GCM
  соблюдены (nonce 12Б случайный, ключи 256 бит).
- Зависимости Go минимальны и только «одобренные» (совместимы с CGO=0).
- SFrame-вставка доступна не во всех браузерах — это честно отражено в UI.
- Не подключаются внешние STUN/TURN/pub-sub — сеть остаётся полностью
  самодостаточной (сужается до одной ЛВС).