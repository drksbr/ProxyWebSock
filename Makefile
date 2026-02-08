SHELL := /usr/bin/env bash

MODULE := github.com/drksbr/ProxyWebSock
CMD := ./cmd/intratun
BIN_DIR := bin
BINARY := $(BIN_DIR)/intratun
ARTIFACT_DIR := build/artifacts
COVER_FILE := $(ARTIFACT_DIR)/coverage.out
PROFILE_CPU := $(ARTIFACT_DIR)/cpu.pprof
PROFILE_MEM := $(ARTIFACT_DIR)/mem.pprof

GO := go
PM ?= bun
WEB_DIR := web
WEB_DIST := internal/relay/dist

GO_FILES := $(shell find . -type f -name '*.go' -not -path './web/node_modules/*')
GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null)
GOTESTSUM := $(shell command -v gotestsum 2>/dev/null)

RELAY_ARGS := relay --agent-config ./config/agents.example.yaml --stream-id-mode=cuid --proxy-listen=:8080 --secure-listen=:443 --socks-listen=:1080 --acme-host=relay.neurocirurgiahgrs.com.br --acme-email=admin@ncr.com.br --acme-cache=/var/lib/intratun/acme --acme-http=:80 --log-level=error
AGENT_ARGS := agent --relay=wss://relay.neurocirurgiahgrs.com.br/tunnel --id=agente01 --token=troque-esta-senha --dial-timeout-ms=30000 --max-frame=8192 --read-buf=16384 --write-buf=16384 --log-level=error


.DEFAULT_GOAL := build

ifeq ($(PM),bun)
  WEB_INSTALL_CMD := bun install
  WEB_BUILD_CMD := bun run build
  WEB_DEV_CMD := bun run dev
else ifeq ($(PM),npm)
  WEB_INSTALL_CMD := npm install
  WEB_BUILD_CMD := npm run build
  WEB_DEV_CMD := npm run dev
else ifeq ($(PM),pnpm)
  WEB_INSTALL_CMD := pnpm install
  WEB_BUILD_CMD := pnpm run build
  WEB_DEV_CMD := pnpm run dev
else ifeq ($(PM),yarn)
  WEB_INSTALL_CMD := yarn install
  WEB_BUILD_CMD := yarn build
  WEB_DEV_CMD := yarn dev
else
  $(error Unsupported package manager "$(PM)". Set PM=bun|npm|pnpm|yarn)
endif

.PHONY: all build fmt vet lint test race bench bench-profile fuzz cover tidy generate tools clean release \
	 run-relay run-relay-debug run-agent run-agent-debug relay-start relay-stop relay-restart \
	 web-install web-build web-dev mkln version-sync update docker-build docker-run docker-push compose-up compose-down profiles

all: build

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(ARTIFACT_DIR):
	@mkdir -p $(ARTIFACT_DIR)

mkln:
	@rm -rf $(WEB_DIR)/dist
	@rm -rf $(WEB_DIST)

version-sync:
	@echo "Synchronizing version metadata..."
	@bun scripts/sync-version.mjs

web-install:
	@echo "Installing web dependencies with $(PM)..."
	@cd $(WEB_DIR) && $(WEB_INSTALL_CMD)

web-build: mkln web-install
	@echo "Building web UI into $(WEB_DIST)..."
	@cd $(WEB_DIR) && $(WEB_BUILD_CMD)
	@mkdir -p $(WEB_DIST)
	@cp -r $(WEB_DIR)/dist/* $(WEB_DIST)/

web-dev: mkln
	@cd $(WEB_DIR) && $(WEB_DEV_CMD)

fmt:
	@$(GO) fmt ./...

vet:
	@$(GO) vet ./...

lint: tools
ifndef GOLANGCI_LINT
	$(error golangci-lint not installed. Run `make tools` first)
endif
	@echo "Running golangci-lint..."
	@$(GOLANGCI_LINT) run --timeout=5m

unit:
	@$(GO) test ./...

test: tools
ifdef GOTESTSUM
	@$(GOTESTSUM) -- -count=1 ./...
else
	@$(GO) test -count=1 ./...
endif

race:
	@$(GO) test -race ./...

bench:
	@$(GO) test -run=^$$ -bench=. -benchmem ./...

bench-profile: $(ARTIFACT_DIR)
	@$(GO) test -run=^$$ -bench=EncodeBinaryFramePooled -cpuprofile=$(PROFILE_CPU) -memprofile=$(PROFILE_MEM) ./internal/protocol
	@echo "CPU profile written to $(PROFILE_CPU)"
	@echo "Memory profile written to $(PROFILE_MEM)"

fuzz:
	@$(GO) test ./internal/protocol -run=^$$ -fuzz=FuzzDecodeBinaryFrame -fuzztime=10s

cover: $(ARTIFACT_DIR)
	@$(GO) test ./... -coverprofile=$(COVER_FILE)
	@$(GO) tool cover -func=$(COVER_FILE)

build: $(BIN_DIR) web-build
	@echo "Building Go binary ($(BINARY))..."
	@$(GO) build -o $(BINARY) $(CMD)

release: clean web-build
	@echo "Building release binaries..."
	@GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN_DIR)/intratun-linux-amd64 $(CMD)
	@GOOS=linux GOARCH=arm64 $(GO) build -o $(BIN_DIR)/intratun-linux-arm64 $(CMD)
	@GOOS=darwin GOARCH=arm64 $(GO) build -o $(BIN_DIR)/intratun-darwin-arm64 $(CMD)
	@GOOS=windows GOARCH=amd64 $(GO) build -o $(BIN_DIR)/intratun-windows-amd64.exe $(CMD)

profiles: bench-profile

update:
	@echo "Updating project from git..."
	@git pull --rebase --autostash

clean:
	@rm -rf $(BIN_DIR) $(ARTIFACT_DIR)

run-relay:
	$(BINARY) $(RELAY_ARGS)

run-relay-debug: build
	$(BINARY) $(RELAY_ARGS) --log-level=debug

run-agent: build
	$(BINARY) $(AGENT_ARGS)

run-agent-debug: build
	$(BINARY) $(AGENT_ARGS) --log-level=debug

relay-start: build
	@mkdir -p $(BIN_DIR)
	@nohup $(BINARY) relay --pid-file=$(BIN_DIR)/intratun.pid >> $(BIN_DIR)/intratun.log 2>&1 &
	@sleep 1
	@echo "Relay running with PID $$(cat $(BIN_DIR)/intratun.pid)"

relay-stop:
	@if [ -f $(BIN_DIR)/intratun.pid ]; then \
		PID=$$(cat $(BIN_DIR)/intratun.pid); \
		kill $$PID && rm -f $(BIN_DIR)/intratun.pid; \
	fi

relay-restart: relay-stop relay-start

docker-build: web-build
	@docker build -t intratun-relay .

docker-run: docker-build
	@docker run --rm -p 8080:8080 -p 8443:8443 intratun-relay

docker-push: docker-build
	@docker tag intratun-relay drks/intratun-relay:latest
	@docker push drks/intratun-relay:latest

compose-up:
	@docker compose up

compose-down:
	@docker compose down

tools:
	@echo "Ensuring development tools are installed..."
	@if [ -z "$(GOLANGCI_LINT)" ]; then \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0; \
	fi
	@if [ -z "$(GOTESTSUM)" ]; then \
		$(GO) install gotest.tools/gotestsum@latest; \
	fi
