GO ?= go
DOCKER ?= docker
KUBECTL ?= kubectl
BINARY ?= build/aegissre
SCAFFOLD_IMAGE := ghcr.io/shanurwan/aegissre@sha256:0000000000000000000000000000000000000000000000000000000000000000
SCAFFOLD_MIGRATION := aegis-postgres-migrate-replace-before-live

.PHONY: help build test test-e2e test-harness test-race vet verify fmt keygen \
	run-monitor run-investigator run-operator run-mcp-read run-mcp-action \
	compose-up compose-down compose-logs manifests-dry-run

help:
	@echo "AegisSRE targets"
	@echo "  build              build $(BINARY)"
	@echo "  test               run all Go package tests"
	@echo "  test-e2e           run the full MCP/A2A/remediation/reporting workflow"
	@echo "  test-harness       test live-k3s acceptance correlation and guardrails"
	@echo "  test-race          run tests with the race detector"
	@echo "  vet                run go vet"
	@echo "  verify             run vet and tests without rewriting files"
	@echo "  fmt                format Go packages"
	@echo "  keygen             generate a disposable Ed25519 delegation keypair"
	@echo "  run-*              run one local process"
	@echo "  compose-up         build and start the fixture topology"
	@echo "  compose-down       stop the fixture topology"
	@echo "  compose-logs       follow fixture logs"
	@echo "  manifests-*        render a fail-closed or policy-gated Kubernetes overlay"
	@echo "  security-dast      ZAP-attack the release image topology (needs Docker)"
	@echo "  security-iast      run the instrumented topology under attack and assess it"
	@echo "  nanda-interop      verify AegisSRE AgentFacts with NANDA's own signing code"

build:
	@mkdir -p $(dir $(BINARY))
	$(GO) build -trimpath -o $(BINARY) ./cmd/aegissre

test:
	$(GO) test ./...

test-e2e:
	@test "$$($(GO) test -list '^TestE2E' ./internal/integration | grep -c '^TestE2E')" -ge 5
	$(GO) test -count=1 -timeout=30s -run '^TestE2E' ./internal/integration

test-harness:
	python -B -m unittest discover -s hack -p '*_test.py'

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

verify: vet test test-harness

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

.PHONY: manifests-production manifests-laboratory manifests-laboratory-execute \
	manifest-policy-overlays live-k3s-acceptance-help

manifests-production:
	$(KUBECTL) kustomize deploy/kubernetes/overlays/production

manifests-laboratory:
	$(KUBECTL) kustomize deploy/kubernetes/overlays/laboratory

manifests-laboratory-execute:
	$(KUBECTL) kustomize deploy/kubernetes/overlays/laboratory/execute

manifest-policy-overlays:
	python scripts/manifest-policy.py --overlay deploy/kubernetes/overlays/production --expected-target replace-before-live --expected-dry-run true --expected-mutations false --expected-image $(SCAFFOLD_IMAGE) --expected-migration-name $(SCAFFOLD_MIGRATION) --profile scaffold
	python scripts/manifest-policy.py --overlay deploy/kubernetes/overlays/laboratory --expected-target aegissre-e2e-canary --expected-dry-run true --expected-mutations false --expected-image $(SCAFFOLD_IMAGE) --expected-migration-name $(SCAFFOLD_MIGRATION) --profile scaffold
	python scripts/manifest-policy.py --overlay deploy/kubernetes/overlays/laboratory/execute --expected-target aegissre-e2e-canary --expected-dry-run false --expected-mutations true --expected-image $(SCAFFOLD_IMAGE) --expected-migration-name $(SCAFFOLD_MIGRATION) --profile scaffold

live-k3s-acceptance-help:
	python hack/e2e-k3s.py --help

.PHONY: security-dast security-iast nanda-interop

IAST_COMPOSE := -f compose.yaml -f security/iast/compose.yaml

security-dast:
	$(DOCKER) build --build-arg GO_VERSION=1.26.10 --tag aegissre:local .
	$(DOCKER) compose up --detach --no-build --wait
	security/dast/scan.sh build/dast; status=$$?; $(DOCKER) compose down --timeout 15; exit $$status

security-iast:
	$(DOCKER) build --file security/iast/Dockerfile --build-arg GO_VERSION=1.26.10 --tag aegissre:iast .
	rm -rf build/iast build/iast-zap && mkdir -p build/iast && chmod 0777 build/iast
	$(DOCKER) compose $(IAST_COMPOSE) up --detach --no-build --wait
	-security/dast/scan.sh build/iast-zap
	$(DOCKER) compose $(IAST_COMPOSE) stop --timeout 30
	security/iast/assess.sh $(IAST_COMPOSE); status=$$?; $(DOCKER) compose $(IAST_COMPOSE) down --timeout 15; exit $$status

NANDA_INDEX_COMMIT := fc9bc8bb9b15a4816123f2347feb25479d5b4ce8
NANDA_SIGNING_SHA256 := e545d8e74bb15bc3dc3a0c19c4ae00f82978a5c039aab6ea083984da692152f3
NODE_IMAGE := node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85

nanda-interop:
	rm -rf build/nanda-interop
	$(GO) run ./hack/nanda-interop build/nanda-interop
	curl -fsSLo build/nanda-interop/signing.ts https://raw.githubusercontent.com/projnanda/nanda-index-v2/$(NANDA_INDEX_COMMIT)/server/src/services/signing.ts
	echo "$(NANDA_SIGNING_SHA256)  build/nanda-interop/signing.ts" | sha256sum -c -
	cp hack/nanda-interop/verify.ts build/nanda-interop/
	$(DOCKER) run --rm --network none -v "$(CURDIR)/build/nanda-interop:/w:ro" -w /w $(NODE_IMAGE) node --experimental-strip-types --no-warnings verify.ts /w
