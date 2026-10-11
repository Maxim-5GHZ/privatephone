# AGENTS.md — privatephone / ПАК АСК

Автономный offline-комплекс связи: один статический Go-бинарник `pp`
+ встроенный React UI + офлайн-карта (OpenLayers, XYZ-тайлы из `/tiles/`).
База `vault.db` шифруется AES-256-GCM, мастер-ключ = `SHA-256(pp.local ‖ pp.key)`
(две половины: локальная + USB). Каждый пакет подписан ECDSA P-256.

Подробности: `README.md` (обзор) + `docs/01-architecture.md` … `docs/06-technologies.md`
(ссылки вида `файл:строка` — точны, им можно верить).

## Команды (только через make / скрипты, не голый go/npm)

```bash
make build   # ui + gentiles --skip-existing + binary -> build/pp
make dev     # Go :8080 + Vite :5173 (прокси /api и /tiles)
make test    # go test ./... + vitest
make cover   # порог покрытия Go >= 80% (union MAX-merge, см. scripts/coverage.sh)
make vet
make tiles LAT=55.75 LON=37.62 ZMIN=0 ZMAX=7 SPAN=1.5  # build-time закачка (редко нужно)
```

Переменные: `PORT` (default `:8080`), `DATA` (`ROOT/data`), `MASTER_USB`
(single-key режим; без него — схема двух половин), `IPS` (SAN TLS-сертификата),
`NODE` (имя узла в половинках). Dev-ключи: `scripts/dev.sh` кладёт их в `data/`.

## Структура

```
server/cmd/server        main: init/run/verify-journal/journal-export/import/vault-backup/restore
server/internal/crypto   ECDSA-канон, master-key + USB-watchdog, mlock, ReplayGuard, CA/TLS
server/internal/db       AES-GCM vault + SQLite в RAM + журнал
server/internal/protocol protocol.go — Frame/Envelope/Verifier (КАНОН, см. ниже)
server/internal/ws       hub, backlog, relay
server/internal/api      REST + signed-middleware + tiles.go + spa fallback; tiles/fetch — докачка
server/internal/web      go:embed dist (UI) и tiles (z0-5 placeholder, перекр. data/tiles/)
server/cmd/gentiles      генератор placeholder-тайлов, флаг --skip-existing (не затирать скачанное!)
frontend/src             React: Login / Карта (OpenLayers) / Чат / Админ
frontend/src/crypto      e2ee.ts, content.ts, signing.ts — КАНОН E2EE, vitest-тесты рядом
frontend/src/views       MapView.tsx (ol), ChatView, AdminView (MapsTab: тайлы/скачивание)
scripts/                 dev.sh, coverage.sh, fetch_tiles.sh (legacy build-time)
```

## Канон (не менять молча — только с тестами и докой)

- Подпись пакетов: канон в `server/internal/protocol/protocol.go` обязан совпадать
  байт-в-байт с `frontend/src/crypto/signing.ts`. Сломал канон — сломал все подписи.
- E2EE-конверт v2 `{v:2, alg:A256GCM, epub, iv, c, k:[{to,salt,iv,ek}]}` (HKDF `pp-e2ee/v2`,
  эфемерный ECDH). v1 читается как legacy — не удалять чтение.
- Журнал: детерминированный id `sender|kind|nonce|ts`, цепь `prev_hash` SHA-256.
  Sneaker-net мешок проверяется целиком (все-или-ничего).
- Тайлы: URL-схема `/tiles/{source}/{z}/{x}/{y}.png`, `source = osm|sat`.
  Порядок приоритетов: `data/tiles/` (custom, перекр.) → embed → 404-PNG fallback.
  OSM attribution обязательно (`© OpenStreetMap contributors`, спутник `© Esri`).

## Запреты

- Не коммитить секреты: `data/`, `*.pem`, `pp.local`, `pp.key`, `vault.db`, `*.db`.
  Dev-данные — только в `ROOT/data/`, никогда в `build/`.
- Не класть большие бинарники/тайлы в git (`build/`, `web/dist`, `web/tiles` — ignored).
- Не менять `docs/` глоссарий молча (узел, vault, половинки, мешок — устоявшиеся термины).
- OSM tile usage policy: User-Agent `privatephone/1.0`, троттлинг, zoom ≤ 16,
  cap ~20k файлов на задачу докачки.

## Тесты и гейты

- `make test` зелёный обязательно; `make cover` ≥ 80%; `go vet` чисто; фронт `tsc -b` strict.
- Бэк: `server/internal/api/e2e_*_test.go` — подписанный REST+WS контур; ломал — чини.
- Фронт: vitest рядом с криптой (`*.test.ts`); MapView правится только с ручной
  проверкой слоёв osm/sat + офлайн (отрубленный инет, карта с `data/tiles` живёт).

## Ловушки (реальные, уже кусались)

- `make build` раньше затирал скачанные тайлы — теперь `gentiles --skip-existing`.
  Реальные тайлы живут в `data/tiles/` (не в embed) и переживают пересборку.
- `server/tmp/` может оказаться под owner root (sudo-запуск) — удалять через sudo.
- `dev.sh` использует single-key режим (`-key`), прод — две половины; не путать.
- Esri-порядок тайлов `tile/{z}/{y}/{x}` (y и x переставлены!) vs OSM `{z}/{x}/{y}`.
- `getUserMedia`/WebRTC — только secure context (нужен `-tls` + импорт `data/ca.crt`).
- Часы: replay-guard ±10 мин; при расхождении `-clock-calibrate` / `-clock-skew`.
