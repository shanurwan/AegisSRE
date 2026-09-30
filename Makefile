GO ?= go
DOCKER ?= docker
KUBECTL ?= kubectl
BINARY ?= build/aegissre

.PHONY: help build test test-race vet verify fmt keygen \
	run-monitor run-investigator run-operator run-mcp-read run-mcp-action \
	compose-up compose-down compose-logs manifests-dry-run manifests-execute

help:
	@echo "AegisSRE targets"
	@echo "  build              build $(BINARY)"
	@echo "  test               run unit tests"
	@echo "  test-race          run tests with the race detector"
	@echo "  vet                run go vet"
	@echo "  verify             run vet and tests without rewriting files"
	@echo "  fmt                format Go packages"
	@echo "  keygen             generate a disposable Ed25519 delegation keypair"
	@echo "  run-*              run one local process"
	@echo "  compose-up         build and start the fixture topology"
	@echo "  compose-down       stop the fixture topology"
	@echo "  compose-logs       follow fixture logs"
	@echo "  manifests-*        render a Kubernetes overlay"

build:
	@mkdir -p $(dir $(BINARY))
	$(GO) build -trimpath -o $(BINARY) ./cmd/aegissre

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

verify: vet test

fmt:
	$(GO) fmt ./...

keygen:
	$(GO) run ./cmd/aegissre keygen

run-monitor:
	$(GO) run ./cmd/aegissre monitor

run-investigator:
	$(GO) run ./cmd/aegissre investigator

run-operator:
	$(GO) run ./cmd/aegissre operator

run-mcp-read:
	$(GO) run ./cmd/aegissre mcp-server --profile=read

run-mcp-action:
	$(GO) run ./cmd/aegissre mcp-server --profile=action

compose-up:
	$(DOCKER) compose up --build

compose-down:
	$(DOCKER) compose down

compose-logs:
	$(DOCKER) compose logs -f

manifests-dry-run:
	$(KUBECTL) kustomize deploy/kubernetes/overlays/dry-run

manifests-execute:
	$(KUBECTL) kustomize deploy/kubernetes/overlays/execute
