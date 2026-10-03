# 03 — Протокол

Формат пакетов, журнал с hash-цепочкой, replay-guard, маршрутизация,
store-and-forward и ретрансляция сигналов звонков/рации.

## 1. Проводной формат пакета

### WS-фрейм (`server/internal/protocol/protocol.go:15-22`)
```json
{
  "sender":    "ПОЗЫВНОЙ",
  "ts":        1750000000,
  "nonce":     "g7fK…",
  "kind":      "message | marker | zone | alert | call_invite | ptt_start | hello …",
  "signature": "MEUCIA…",
  "data":      { …сырой JSON, ровно те байты, что подписаны… }
}
```
Клиент сериализует идентично (`buildWSFrame`, `signing.ts:113-119`).

### REST-эквивалент
Поля идут в HTTP-заголовках (`X-Sender/X-Kind/X-TS/X-Nonce/X-Signature`), тело —
сырые JSON-байты `data` (сервер собирает `Envelope`, `server.go:134-156`;
лимит тела 1 MiB). Клиент — `signing.ts:96-103` + `api/client.ts:4-18`.

### Подписываемый канон — см. `02-cryptography` §3.
`v=1\nkind=…\nsender=…\nts=…\nnonce=…\n<данные>` — байт-в-байт на обеих сторонах;
тело не переформатируется.

## 2. Виды пакетов (`kind`)

### Журналируемые события (сохраняются в `packets`, доставляются офлайн)
| kind | Смысл | Источник |
|---|---|---|
| `marker`, `marker_update`, `marker_delete` | гео-метки на карте | dispatch.go:31-42 |
| `message` | сообщение/группа/директ (поле `recipient`) | dispatch.go:43-46 |
| `ack` | квитанция доставки пакетов (`{ids}`) | dispatch.go:47-48 |
| `alert`, `alert_ack`, `alert_clear` | тревоги SOS/СБОР/Инфо, подтверждение, отбой | dispatch.go:49-64 |
| `zone`, `zone_update`, `zone_delete` | зоны-полигоны | dispatch.go:65-76 |
| `revoke_subscriber`, `unrevoke_subscriber` | CRL-команды админа | import.go:155-157 |

### Эфемерные сигнальные (релей, НЕ журналируются)
| kind | Смысл |
|---|---|
| `hello` | аутентификация WS-сессии (не пишется) |
| `call_invite`, `call_accept`, `call_reject`, `call_bye`, `ice` | сигналинг звонка 1:1 (relay.go:11-31) |
| `ptt_start`, `ptt_end`, `ptt_talking`, `ptt_offer`, `ptt_answer`, `ptt_ice` | сигналинг рации (relay.go:36-51) |

## 3. E2EE-конвертное содержимое

Любое журналируемое событие может нести опциональное поле `enc` внутри `data`.
Сервер **никогда не вскрывает** его; вместо этого он подменяет читаемые поля
маркером `"enc"`:

| тип | что подменяется | источник |
|---|---|---|
| метка | `lat/lon=0`, `type="enc"`, `desc=enc` | ingest.go:30-33 |
| обновление метки | `type/desc="enc"` | ingest.go:64-66 |
| сообщение | `body=enc` | ingest.go:116-119 |
| тревога | `atype/atext="enc"` (при этом whitelist-тип `sos/gather/info` пропускается) | ingest.go:159-164 |
| зона | `name/color="enc"`, `points=enc`, проверка ≥3 точек пропускается | ingest.go:238-254 |

Детектор — `encCargo(data)` (dispatch.go:88-99): ищет непустой `enc`, не глядя на
его структуру. Так узел/БД держат только шифротексты, а «красивое» содержимое
(координаты метки, текст чата, полигон зоны) рендерится в браузере после
расшифровки (см. `02-cryptography` §4 и `01-architecture` §3.10-11).

## 4. Журнал: tamper-evident hash-цепочка

Хранилище — таблица `packets` внутри зашифрованного vault.db (db.go:149-159).

### Детерминированный ID (дедупликация)
```
PacketID = sha256("pp-packet-v1\x00" + sender \x00 kind \x00 nonce \x00 ts)[:16 hex]
```
store.go:506-509. ID не зависит от порядка записи — повторный импорт того же
подписанного пакета не дублируется.

### Цепь хэшей (chain)
Каждая строка хранит `prev_hash` — значение цепи предыдущей:
```
chainHash(prev, id, sender, kind, ts, nonce, recipient, signature, payload) =
  sha256("pp-journal-v1\x00" ‖ prev_hash ‖ id ‖ sender ‖ kind ‖ ts ‖ nonce ‖
          recipient ‖ signature ‖ payload)
```
- генезис: `prev_hash=""`;
- «голова» журнала = пересчитанное значение последней строки (`chainHeadOf`,
  store.go:558-571);
- `AddPacket` пишет транзакционно `BEGIN → chainHeadOf → INSERT → COMMIT`
  (store.go:524-549) — параллельные писатели не перепутают порядок.

### Проверка целостности
`VerifyJournal` (store.go:604-626) пересчитывает цепь по `ORDER BY rowid`:
- обрыв → `(index, …)` первой расхожей строки;
- `-1` → цепь цела + актуальная голова.

CLI: `pp verify-journal` — печатает `OK — N rows intact, head=…` или
`TAMPERED at journal index %d` и **exit code 1** (main.go:282-309). Отсюда —
«журнал доказывает подмену/удаление/вставку истории»: любой мешок можно
перепроверить на любом узле.

### Миграции
`backfillChain` (db.go:274-311) и `ensureColumn …prev_hash` (db.go:198-200)
идемпотентно достраивают цепь для строк, написанных до обновления.

## 5. Мешок («bag») журнал-экспорта / импорта

Формат (JSON): `{"head": "<голова>", "entries": [JournalEntry…]}` (main.go:343-345;
REST — handlers.go:264, POST .../journal/import — handlers.go:280-294).

- **Экспорт**: CLI `pp journal-export [-after TS] -out FILE` → `ListJournal(ctx,
  afterTS)` (store.go:580-599) — только `ts ≥ after`, строго по rowid; или
  REST `GET /api/v1/journal?after=<unix-ts>` (admin).
- **Импорт** `pp journal-import -in FILE` → `Hub.ImportBag` (import.go:46-113),
  «all-or-nothing», проверки по порядку:
  1. мешок пуст → ничего;
  2. первый ID уже в журнале → весь мешок `SkippedDup` (дедуп/идемпотентность);
  3. **непрерывность с локальным журналом**: `localHead == entries[0].PrevHash`
     (import.go:69-73);
  4. внутренняя цепь: `db.VerifyBag(entries)` (store.go:656-668);
  5. подписи к записям: `ver.VerifyStored` по локальному реестру (без replay-
     guard и свежести — события сохраняют исходные ts/nonce, import.go:81-95);
  6. воспроизведение сайд-эффектов `replayImport` (метки/сообщения/
     тревоги/зоны/CRL); цель отсутствует → `SkippedCtx`, но строка пишется —
     цепь сходится;
  7. `revoke/unrevoke` разыгрывается только админом (`replayRevoke`,
     import.go:175-195).
- При отказе — exit 1 (main.go:409-411); успех: `added_journal=… skipped_… head=…`.
- REST-версия требует `signedAdmin`.

## 6. Маршрутизация «кому доставить»

Постоянных «каналов/подписок» в меше нет — маршрутизация всегда явная, через
поле `recipient` (или `to` у сигналов).

### Разбор адресата (`parseRecipients`, relay.go:73-84; фронт `recipientList`,
`content.ts:5-14`)
```
""         → broadcast (всем, включая автора)
"callsign" → один адресат
["a","b"]  → группа (JSON-массив)
```

### Доставка (`deliver`, relay.go:90-112)
- Множество = автор + адресаты; broadcast при пустом.
- SQL-запрос для недоставленных (`UndeliveredPacketsFor`):
  `recipient='' OR sender=? OR recipient=? OR recipient LIKE '%callsign%'`
  (store.go:690-708) — то есть «мои + адресованные мне + бродкаст» и для
  отстающих групп.
- **Отозванные (revoked) пропускаются в обоих режимах** (relay.go:100-102) —
  CRL работает и на лету на delivered-путе.

### Поток по сети (кратко)
`deliver(b, recips, sender)` → `tryEnqueue` неблокирующе добавляет байты в канал
`send` клиента (client.go:44-50); полный канал → медленный клиент **закрывается**
(защита остального меша от backpressure, hub_test.go:278-316); запись байтов
делает единственный `writePump` (client.go:61-87) с периодическим Ping 30 с и
write-timeout 10 с.

## 7. Store-and-forward (офлайн-очередь) и ack

- Все подписанные входящие события в журнале (`AddPacket`, store.go:524),
  флаг `delivered=0`.
- При `hello` (после верификации подписи, hub.go:61-145):
  1. `snapshot` — текущее состояние `markers/messages/alerts/zones/online`
     (только то, что адресовано мне: `ListMessagesFor`, store.go:484-502);
  2. `packets {items}` — всё недоставленное: `UndeliveredPacketsFor(ctx, me)`.
- Клиент, получив `packets`, собирает `ids` и шлёт подписанный `ack` →
  `handleAck` (ingest.go:131-139) → `MarkDelivered` (store.go:710-730).
- Идемпотентность: повторные `ack` не вредят; повторная доставка пакетов не
  дублирует состояния (детерминированные ID, upsert-семантика в useMesh).
- REST-зеркало: `GET /api/v1/pending` (handlers.go:62-69).

## 8. Релей звонков и рации

### Звонок 1:1 (`relayCall`, relay.go:11-31)
1. Читает `data.to`.
2. `target := h.findClient(to)` (hub.go:172-181, поиск по id клиента =
   подписанному callsign).
3. Цель офлайн → отправителю `call_error {to, error:"offline"}` (relay.go:20-24).
4. Цель онлайн → релей **байт-в-байт исходного подписанного фрейма**
   `json.Marshal(f)` (relay.go:27-30). НЕ пере-подписывается и НЕ журналируется —
   эфимерно. Получатель сам верифицирует подпись автора.

### Рация (`relayPTT`, relay.go:36-51)
- `to` = один callsign или JSON-массив (`relayRecipients`, relay.go:55-69).
- Релей через `h.deliver(b, recips, sender)` — каждый участник + автор; тоже
  эфимерно, без журнала (relay.go:33-35).
- `to` пуст → отказ (relay.go:40-41), PTT требует явного списка.

### Безопасность релея
- Сервер верифицирует подпись КАЖДОГО фрейма до маршрутизации (dispatch.go:21-25);
  невалидный дропается с логом, nonce не тратится.
- Сигналы несут `to/n/talks` открытыми (для маршрутизации), а
  `sdp/candidate/sframe` — только внутри E2EE-конверта `enc` (см.
  `02-cryptography` §5).

## 9. WebSocket-сессия: жизненный цикл

1. `GET /api/v1/ws` (апгрейд). `OriginPatterns=["*"]` — origin НЕ является
   границей доверия: граница — криптография каждого фрейма (hub.go:62-64).
2. Регистрация `client`; запускается `writePump` (ping 30 с).
3. Читающий цикл: read timeout 90 с; каждый кадр — в `dispatch`.
4. `hello` → `setID` + `pushBacklog` + `broadcastPresence`. До id клиент
   «анонимный»: в `Online()` и маршрутизации не участвует.
5. Отключение → удаление из map + `broadcastPresence` (список online
   обновляется у всех, hub.go:75-80).
6. Backpressure: `tryEnqueue` не блокирует; переполнение `send` (256) →
   клиент закрывается (hub.go:18-20).

## 10. Коды ошибок верификации

`protocol.go:49-54`: `ErrReplay`, `ErrUnknownSender`, `ErrBadSignature`,
`ErrRevoked`. В REST: 401 для любых сбоев подписи (server.go:98-111); 403 для
не-admin при `signedAdmin` (server.go:114-132). В WS: отозванного кикают с
`StatusPolicyViolation "revoked"`.