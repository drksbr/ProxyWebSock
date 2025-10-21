SHELL := /usr/bin/env bash

WEB_DIR := web
WEB_NODE_MODULES := $(WEB_DIR)/node_modules
GO_CMD := ./cmd/intratun
BIN_DIR := bin
BINARY := $(BIN_DIR)/intratun

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

.PHONY: all build web-install web-build go-build clean web-dev run docker-build docker-run compose-up compose-down

all: build

$(WEB_NODE_MODULES):
	@echo "Installing web dependencies with $(PM)..."
	@cd $(WEB_DIR) && $(WEB_INSTALL_CMD)

web-install: $(WEB_NODE_MODULES)

web-build: $(WEB_NODE_MODULES)
	@echo "Building web UI into internal/relay/dist..."
	@cd $(WEB_DIR) && $(WEB_BUILD_CMD)

go-build: web-build
	@echo "Building Go binary ($(BINARY))..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(BINARY) $(GO_CMD)

build: go-build

run-relay: web-build go-build
	./intratun relay   --proxy-listen=:80   --secure-listen=:443   --socks-listen=:1080   --agents=myagent:supersecret   --acl-allow='^.*:443$'   --acme-host=relay.neurocirurgiahgrs.com.br   --acme-email=admin@ncr.com.br   --acme-cache=/var/lib/intratun/acme   --acme-http=:80

run-agent: go-build
	./intratun agent   --server=relay.neurocirurgiahgrs.com.br:443   --agent-name=myagent   --agent-secret=supersecret 

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
