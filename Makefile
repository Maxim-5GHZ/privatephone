GO      := go
NPM     := npm
ROOT    := $(CURDIR)
BUILD   := $(ROOT)/build
DATA    := $(ROOT)/data
# path to the USB master key (or dev file)
MASTER_USB ?= $(DATA)/pp.key
ADMIN      ?= $(DATA)/admin.pem
PORT       ?= :8080
# comma-separated LAN IPs embedded into the self-signed TLS cert SAN (any, e.g. "192.168.1.10")
IPS        ?=

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/arm64

.DEFAULT_GOAL := all

.PHONY: help all ui gentiles build run dev init tiles test vet cover cross clean

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "} {printf "  %-12s %s\n", $$1, $$2}'

all: build ## default: ui + single binary for this host

## --- UI / embeds -------------------------------------------------------------

ui: ## build React frontend and embed into the server package
	cd "$(ROOT)/frontend" && $(NPM) run build
	rm -rf "$(ROOT)/server/internal/web/dist"/*
	cp -r "$(ROOT)/frontend/dist"/* "$(ROOT)/server/internal/web/dist/"

gentiles: ## generate offline placeholder tiles (z0-5) for the embedded map
	cd "$(ROOT)/server" && $(GO) run ./cmd/gentiles

## --- Build -------------------------------------------------------------------

build: ui gentiles ## single binary for the current host
	cd "$(ROOT)/server" && CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o "$(BUILD)/pp" ./cmd/server
	@echo "binary: $(BUILD)/pp"

cross: ui gentiles ## binaries for all PLATFORMS -> build/pp-<os>-<arch>[.exe]
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo ">> $$os/$$arch"; \
		cd "$(ROOT)/server" && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags="-s -w" -o "$(BUILD)/pp-$$os-$$arch$$ext" ./cmd/server || exit 1; \
	done
	@ls -lh "$(BUILD)"/pp-*

## --- Deploy / run ------------------------------------------------------------

init: ## create master key on the USB device + admin key for the operator
	mkdir -p "$(DATA)"
	cd "$(ROOT)/server" && $(GO) run ./cmd/server init -key "$(MASTER_USB)" -data "$(DATA)" -admin-out "$(ADMIN)" $(if $(IPS),-ips "$(IPS)",)
	@echo
	@echo "master key : $(MASTER_USB)  (keep on the USB flash, remove after copy)"
	@echo "admin key  : $(ADMIN)"
	@echo "TLS cert   : $(DATA)/tls.crt  (import into every client once, WebRTC needs HTTPS)"

run: ## run the server (binary must be already built with `make build`)
	"$(BUILD)/pp" run -port "$(PORT)" -data "$(DATA)" -key "$(MASTER_USB)" -tls

dev: ## dev loop: Go server on :8080 + Vite on :5173 (no Docker)
	"$(ROOT)/scripts/dev.sh"

tiles: ## download real OSM tiles for a region into the embedded tile set
	"$(ROOT)/scripts/fetch_tiles.sh"

## --- Quality -----------------------------------------------------------------

COVER_THRESHOLD ?= 80

test: ## run Go tests + frontend unit tests
	cd "$(ROOT)/server" && $(GO) test ./...
	cd "$(ROOT)/frontend" && $(NPM) test

cover: ## cross-package Go coverage gate (>= COVER_THRESHOLD)
	"$(ROOT)/scripts/coverage.sh"

vet: ## go vet
	cd "$(ROOT)/server" && $(GO) vet ./...

clean: ## remove build artifacts and generated embeds
	rm -rf "$(ROOT)/build" "$(DATA)"
	rm -rf "$(ROOT)/server/internal/web/dist"/* "$(ROOT)/server/internal/web/tiles"/*
	touch "$(ROOT)/server/internal/web/dist/.gitkeep" "$(ROOT)/server/internal/web/tiles/.gitkeep"
	cd "$(ROOT)/frontend" && rm -rf dist