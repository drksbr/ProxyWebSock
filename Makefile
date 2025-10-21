SHELL := /usr/bin/env bash

WEB_DIR := web
WEB_NODE_MODULES := $(WEB_DIR)/node_modules
GO_CMD := ./cmd/intratun
BIN_DIR := bin
BINARY := $(BIN_DIR)/intratun
PID_FILE := $(BIN_DIR)/intratun.pid
LOG_FILE := $(BIN_DIR)/intratun.log

RELAY_ARGS := relay --stream-id-mode=cuid --proxy-listen=:8080 --secure-listen=:443 --socks-listen=:1080 --agents=Veloz:supersecret --acl-allow='^.*:443$$' --acme-host=relay.neurocirurgiahgrs.com.br --acme-email=admin@ncr.com.br --acme-cache=/var/lib/intratun/acme --acme-http=:80
AGENT_ARGS := agent --relay=wss://relay.neurocirurgiahgrs.com.br/tunnel --id=Veloz --token=supersecret --dial-timeout-ms=5000 --max-frame=32768 --read-buf=65536 --write-buf=65536

PM ?= bun

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

.PHONY: all build web-install web-build go-build clean web-dev run run-relay run-agent relay-start relay-stop relay-restart docker-build docker-run compose-up compose-down

all: build

$(WEB_NODE_MODULES):
	@echo "Installing web dependencies with $(PM)..."
	@cd $(WEB_DIR) && $(WEB_INSTALL_CMD)

update:	
	@echo "Updating project from git..."
	@git pull origin main

mkln:
	@rm -rf $(WEB_DIR)/dist
	@rm -rf $(CURDIR)/internal/relay/dist
	@mkdir -p $(CURDIR)/internal/relay/dist
	@ln -sfn $(CURDIR)/internal/relay/dist $(WEB_DIR)/dist
	@echo "Created symlink $(WEB_DIR)/dist -> $(CURDIR)/internal/relay/dist"

web-install: $(WEB_NODE_MODULES)

web-build: $(WEB_NODE_MODULES)
	@echo "Building web UI into internal/relay/dist..."
	@cd $(WEB_DIR) && $(WEB_BUILD_CMD)

go-build: web-build
	@echo "Building Go binary ($(BINARY))..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(BINARY) $(GO_CMD)

build: mkln go-build

run-relay: 
	$(BINARY) $(RELAY_ARGS)

run-agent: 
	$(BINARY) $(AGENT_ARGS)

relay-start: go-build
	@if [ -f $(PID_FILE) ]; then \
		echo "PID file $(PID_FILE) already exists. Is the relay running?"; \
		exit 1; \
	fi
	@echo "Starting relay daemon..."
	@nohup $(BINARY) $(RELAY_ARGS) --pid-file=$(PID_FILE) >> $(LOG_FILE) 2>&1 &
	@sleep 1
	@if [ ! -f $(PID_FILE) ]; then \
		echo "Failed to create PID file at $(PID_FILE). Check $(LOG_FILE) for details."; \
		exit 1; \
	fi
	@echo "Relay running with PID $$(cat $(PID_FILE))"

relay-stop:
	@if [ ! -f $(PID_FILE) ]; then \
		echo "PID file $(PID_FILE) not found. Relay not running?"; \
		exit 0; \
	fi
	@PID=$$(cat $(PID_FILE)); \
	if [ -z "$$PID" ]; then \
		echo "PID file empty. Removing stale file."; \
		rm -f $(PID_FILE); \
		exit 0; \
	fi; \
	if kill -0 $$PID 2>/dev/null; then \
		echo "Stopping relay (PID $$PID)..."; \
		kill $$PID; \
	else \
		echo "Relay process $$PID not running. Cleaning up stale PID file."; \
	fi
	@rm -f $(PID_FILE)

relay-restart:
	@$(MAKE) relay-stop
	@$(MAKE) relay-start

web-dev:
	@cd $(WEB_DIR) && $(WEB_DEV_CMD)

clean:
	@rm -rf $(BIN_DIR)

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
