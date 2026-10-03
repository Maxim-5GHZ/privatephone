# 04 — Развёртывание

Сборка, установка узла, все подкоманды бинаря, данные, резерв/восстановление и
нештатные ситуации.

## 1. Требования хоста

- **Ноль зависимостей** на целевой машине: нужен только сам бинарник (статика,
  `CGO_ENABLED=0`), папка `data/` рядом и USB-флешка.
- Для **сборки**: Go ≥ (см. `server/go.mod`), Node.js/npm (фронтенд), make,
  сеть для npm в момент сборки (один раз).
- Для **webRTC** на устройстве абонента: HTTPS (secure context) — сертификат
  узла подписывается внутренним CA, один раз импортируем `data/ca.crt`
  (см. §6).

## 2. Что стоит рядом с бинарником (dir-orientation)

```
<папка оператора>/pp        — бинарь
data/                        — default -data  (= <папка бинарника>/data)
  vault.db                   — зашифрованная база (AES-256-GCM)
  pp.local                   — половина-A мастер-ключа (только произв. режим)
  admin.pem                  — ключ оператора для выпуска абонентов
  ca.crt, ca.key             — внутренний CA меша
  tls.crt, tls.key           — HTTPS/WSS сертификат узла
data/pp.key (в dev)          — полный мастер-ключ (резервный/single-key режим)
```
Правило: **бинарник живёт в user-директории оператора; данные — рядом; флешка
несёт только половину ключа** (main.go:81-82, README:35-36).

## 3. Сборка

```
make build        # = ui (frontend→embed) + gentiles (тайлы) + go build → build/pp
make cross        # то же для linux/amd64, linux/arm64, windows/amd64, darwin/arm64
make ui           # vite build → server/internal/web/dist (embed через go:embed)
make gentiles     # процедурные тайлы z0-5 → server/internal/web/tiles
```
- `Makefile:27` (`all`) = `build`.
- Сборка одного статического бинаря: `CGO_ENABLED=0 go build -trimpath
  -ldflags="-s -w"` (Makefile:42).
- Встраивание UI: `//go:embed all:dist` и `//go:embed all:tiles`
  (`server/internal/web/web.go:10-13`).
- На хосте-устройстве после сборки раздаётся ТОЛЬКО `build/pp` (+при желании
  `data/` уже проинициализированную, +флешку). Node/Go на устройстве не нужны.

### Пересобранный бинарь и встроенный контент
Помните: `make build` компилирует фронтенд ВНУТРЬ сервера. Поменяли React →
нужно `make build` (или `make ui && make build`), иначе бинарь отдаёт старый UI.

## 4. Первичное развёртывание (два пути)

### А. Визард «с нуля» (нулевые флаги, рекомендуемый сценарий деплоя)
```
cd <папка оператора>
./pp run                # на устройстве с вставленной ЧИСТОЙ флешкой
```
Что произойдёт (main.go:599-749, usb_common.go):
1. `vault.db` не найден → `firstRun=true`.
2. `resolveKeySource` — локальной половины нет → `resolveUsbCreate`:
   - ищутся **чистые** съёмные носители (не те, где уже есть `pp.key` любого
     узла — перезапись чужого ключа запрещена, usb_common.go:263-305);
   - одна флешка → автоматически (в неинтерактивной консоли); несколько →
     интерактивный выбор, либо `-key`;
3. Создаются половины `pp.local` + `pp.key` (nodeID общий, имя из `-node` или
   автоген `node-<hex>`), vault, `admin.pem`, CA+TLS (SAN: автоопределённый
   LAN IP, `firstLANIPv4`); старт по **https** (TLS включается автоматически,
   main.go:625-631).
4. Печатаются инструкции: адрес, admin.pem, пути, предупреждения (не вынимать
   флешку; мешок; потери) — `printFirstRun` (usb_common.go:340-366).
5. Повторный запуск: тот же `./pp run` → `resolveUsbReuse` находит ту же флешку
   того же NodeID → «мастер-ключ из половин», старт.

### Б. Явное развёртывание с «пакетом вещей»
```
./pp init -node ТАНЖЕР -ips 192.168.1.10 -rescue-out <сейф>/танжер.rescue
```
- `-ips` кладёт LAN-IP в SAN TLS-сертификата (важно для входа по IP с
  абонентов).
- `-rescue-out` пишет **полный мастер-ключ** в указанный файл (в сейф) — это
  единственный способ восстановить базу при потере флешки ИЛИ `pp.local` (см. §9).
- `-key PATH` — опустить halves-процедуру и использовать готовый полный ключ
  (резерв/тест).
- Флаги Init: `-data`, `-admin-out`, `-no-tls`, `-node`, см. usage (main.go:69-82).

`make init` заполняет те же флаги из переменных `MASTER_USB/RESCUE/NODE/IPS`.

## 5. Запуск узла (`pp run`)

```
./pp run                          # производственный режим, ключ = половины (pp.local + флешка)
./pp run -key data/pp.key         # резервный/dev режим, полный ключ одним файлом
./pp run -port :8080 -data data -tls
./pp run -port :8080 -data data -key data/pp.key -tls   # наш dev-флоу (см. §10)
```
Флаги: `-port`, `-data`, `-key`, `-node`, `-watch`(=true), `-persist`(5s),
`-clock-skew`(10m), `-clock-calibrate`, `-tls`.

Поведение:
- `-tls` использует `data/tls.crt`+`tls.key`; **при первом запуске без флагов
  включается автоматически** (WebRTC нужен secure context).
- `-watch` (`mk.Watch(time.Second, …)`): флешка извлечена → ключ затёрт, процесс
  завершён (~1 с, main.go:736-744).
- Персист: снапшот vault каждые `-persist` 5 с (main.go:697).
- `-clock-calibrate`: сервер обучается смещению часов по admin-пакетам (максимум
  ±30 мин — см. `02-cryptography` §3).

### Убедиться, что узел живой
`GET https://<ip>:8080/api/v1/health` → `server.go:40`; открой `https://<ip>:8080`
в браузере (нужен доверенный `ca.crt`, §6).

## 6. Доверие TLS на клиентах (один раз на устройство)

```
sudo scripts/install_ca.sh data/ca.crt   # Linux/macOS; Windows: Import-Certificate
```
- Что делает: помещает корень меша в system trust store (Linux:
  `/usr/local/share/ca-certificates` + `update-ca-certificates`; macOS:
  `security add-trusted-cert`; Windows: PowerShell `Import-Certificate`).
- После импорта `https://<ip>:8080` открывается без ругани; WebRTC
  (`getUserMedia`) разрешён. Один корень на весь меш.

## 7. Офлайн-карта: заглушки и реальные тайлы

- `make gentiles` — процедурные PNG 256×256, z0–5, терраформ из широтной зоны +
  детерминированная вариация от хэша `z/x/y` (`cmd/gentiles/main.go:71-99`).
- Реальные тайлы OSM комнаты:
  ```
  ZMIN=0 ZMAX=7 LAT=55.75 LON=37.62 SPAN=1.5 make tiles
  ```
  `scripts/fetch_tiles.sh`: качает `tile.openstreetmap.org/{z}/{x}/{y}.png`
  (не перекачивает существующие), после — `make build` (перевстраивание в бинарь).

## 8. Эксплуатация: подкоманды бинаря

| Команда | Назначение | Ключевое |
|---|---|---|
| `pp run` | запуск узла | см. §5 |
| `pp verify-journal [-data] [-key]` | проверка целостности журнала | exit 1 при обрыве цепи |
| `pp journal-export [-after TS] [-out FILE]` | выгрузка мешка (sneaker-net) | stdout при `-out -` |
| `pp journal-import -in FILE` | импорт мешка на узел | идемпотентно; exit 1 при отказе |
| `pp vault-backup -out FILE` | бэкап базы в tar.gz | узел должен быть ОСТАНОВЛЕН |
| `pp vault-restore -in FILE [-force]` | развернуть бэкап | нужен ключ / pp.local |
| `pp version` | версия | — |

Детали форматов и проверок — в `03-protocol` §5 (журнал) и §9 (бэкап).

## 9. Резерв и восстановление

### Инвариант безопасности
Мастер-ключ из двух половин означает: потеря флешки **ИЛИ** `pp.local` → база
неоткрываема. Поэтому при развёртывании сразу делают полный ключ в сейф
(`-rescue-out`) — это «эскейп-хэтч».

### vault-backup / vault-restore (`main.go:442-569`)
- Упаковка: tar.gz `manifest.json` (`format: privatephone-vault-backup-v1`) +
  sha256 файлов `vault.db/tls.crt/tls.key/ca.crt/ca.key/admin.pem`.
- Восстановление на чистой машине: требуется `-key` (полный ключ из сейфа) или
  перенос `data/pp.local`. Отказ перезаписывать существующую базу без `-force`.
- После распаковки — открытие vault ключом и **пересчёт журнала** (verify).

### Потеря флешки → восстановление
1. Достань копию полного ключа из сейфа (`*.rescue`).
2. `pp run -key <rescue>` — сервер открывает базу одним ключом (резервный
   режим). Работать дальше можно, но halves-гарантии нет.
3. Для возврата к halves-модели: `pp init` на новом наборе половин + перенос
   данных журналом-мешками (см. `05-usecases` §7).

### Проверка журнала (tamper-evident)
Любой мешок можно проверить на любом узле без ключей данных: `verify-journal`
и `journal-import` пересчитывают цепь — подмена/удаление/вставка реалистично
детектируются.

## 10. Dev-режим (без флешки, single-key)

`make dev` → `scripts/dev.sh`:

```
1. ключи нет → go run ./cmd/server init -key data/pp.key   (полный ключ, single-key)
2. UI-embed не собран → frontend build → server/internal/web/dist
3. gentiles (тайлы-заглушки)
4. backend: go run ./cmd/server run -port :8080 -data data -key data/pp.key -watch=false
5. frontend: vite → :5173  (proxy /api и /tiles → :8080, vite.config.ts:9-18)
```
- Используется **полный ключ** `data/pp.key` вместо половин — dev не требует
  флешки и `pp.local`. Watchdog выключен (`-watch=false`).
- Vite на `:5173` — live-версия фронта; Go на `:8080` — бэкенд и файлы.
  Реальные устройства подключаются к :8080 (или вообще `make run`).
- ВАЖНО: это dev-режим. Производственный флоу halves + флешка см. §4-5.

## 11. Нештатные ситуации: чеклист

| Ситуация | Диагностика | Действие |
|---|---|---|
| Флешка вынута в работе | процесс завершён, ключ затёрт | вставить флешку, `pp run` снова |
| База «не открылась» | `vault decrypt failed` | неверный ключ/подмена: проверить половины/`-key`, `verify-journal` |
| Мешок не импортируется | exit 1, причина в выводе | обрыв цепи/не та голова/не та подпись: экспорт с `-after` зоны обрыва |
| Абонент «отозван» | 401/кик «revoked» | `unrevoke` админом, пере-логин |
| Браузер ругается на сертификат | TLS warning | импортировать `ca.crt` (install_ca.sh) |
| Часы клиентов «прыгают» (ложные replay) | логи `ErrReplay` | `-clock-calibrate` на сервере |
| Порт занят | `listen … :8080` | `-port :8081` или stop другого процесса |

## 12. Полезные переменные Makefile

`PORT`, `DATA`, `ADMIN`, `NODE`, `IPS`, `MASTER_USB`, `RESCUE`, `PLATFORMS`,
`COVER_THRESHOLD`. См. `make help`.