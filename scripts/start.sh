#!/usr/bin/env bash
# «ПриватФон» — запуск узла одной командой / двойным кликом.
# Мастер-ключ должен находиться на USB-флешке (пустая флешка подойдёт —
# ключ создастся на ней автоматически).
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/pp"
if [ ! -x "$BIN" ]; then
  BIN="$HERE/build/pp"
fi

cd "$HERE"
exec "$BIN" run