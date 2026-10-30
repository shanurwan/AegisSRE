# Contributing

Thanks for helping make AegisSRE safer and more useful.

This project intentionally values a narrow, explainable capability over a broad automation surface. A new tool or action is a security-boundary change, not merely a convenience API.

## Before you start

- For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
- For a large protocol, domain, tool, or policy change, open a design issue before implementation.
- Keep pull requests focused. Do not combine a new remediation action with unrelated refactoring or dependency upgrades.
- Never use a production cluster, credential, key, or customer log in a test or example.

## Development setup

Prerequisites:

- Go 1.26.10 or newer (CI and the release image pin 1.26.10)
- Docker with Compose for the local topology
- `kubectl` only for rendering/validating Kubernetes manifests

```bash
git clone https://github.com/shanurwan/AegisSRE.git
cd AegisSRE
go mod download
go test ./...
go vet ./...
```

The Makefile provides shortcuts:

```bash
make verify
make build
make compose-up
```

Keep `.env` untracked. Generate only disposable local keys with:

```bash
go run ./cmd/aegissre keygen
```

## Architectural rules

The dependency direction is:

```text
transport/adapters/platform -> application -> core model/ports
```

- `internal/core/model` must not import A2A, MCP, Kubernetes, Victoria, HTTP, or platform packages.
- `internal/core/ports` exposes project-owned types, not SDK or Kubernetes types.
- Application services orchestrate ports and domain values; they do not construct HTTP clients or read environment variables.
- Transport packages validate protocol envelopes and translate them into domain values.
- Adapters enforce their own bounds even when an upstream caller already validated input.
- Process wiring and configuration belong at the composition edge under `cmd`/`internal/platform`.

See [architecture.md](docs/architecture.md).

## Safety rules for tools and actions

An acceptable read tool has:

- a typed input/output schema;
- namespace, time, result-count, and byte limits;
- no raw query or arbitrary URL field;
- deterministic validation and useful denial errors;
- tests proving boundary rejection.

An acceptable action has:

- a closed action type and exact target/parameters;
- a documented Kubernetes verb/resource requirement;
- resource-version/generation or equivalent preconditions;
- dry-run behavior;
- independent grant verification in Operator and action MCP;
- replay/idempotency behavior;
- an observation-based postcondition;
- a rollback/escalation story;
- adversarial and duplicate-delivery tests.

Do not add shell, pod exec, generic patch/apply/delete, arbitrary PromQL/LogsQL, secret read, RBAC mutation, token creation, or a cluster-admin requirement.

## Protocol changes

A2A and MCP versions are wire contracts, not marketing labels.

- Keep A2A Agent Cards, version headers, tasks/messages/parts, and errors aligned with A2A v1.0.
- Keep MCP Streamable HTTP and tool behavior aligned with revision `2026-07-28`.
- Use the official Go SDKs pinned in `go.mod`.
- Add interoperability/conformance evidence when claiming protocol support.
- Preserve structured domain payloads; do not authorize from natural-language text.

When upgrading an SDK, describe the wire-level effect and test both supported and rejected protocol versions.

## Testing expectations

Run:

```bash
go test ./...
go test -race ./...
go vet ./...
```

Format Go code with `gofmt`/`go fmt`. New behavior should include focused unit tests and, where applicable:

- domain state transition tests;
- grant tampering, expiry, audience, binding, and replay tests;
- adapter bounds and malformed-response tests;
- A2A/MCP serialization/interoperability tests;
- Kubernetes fake-client tests for dry-run, conflict, and exact patch shape;
- fixture integration tests that assert no side effect by default.

Do not describe a test or feature as implemented until it exists and passes in the repository.

## Documentation and configuration

Update documentation in the same pull request when changing:

- CLI commands or flags;
- environment variables/defaults;
- tool names or schemas;
- Agent Cards/protocol versions;
- grant claims/policy decisions;
- RBAC, NetworkPolicies, images, ports, or telemetry endpoints;
- deployment safety gates.

`.env.example` must contain placeholders only. Kubernetes Secret examples must never contain generated values.

## Branch and pull request workflow

`main` is protected by the ruleset in [`.github/rulesets/main.json`](.github/rulesets/main.json). Every change, including the maintainer's, lands through a pull request:

1. Fork the repository (or branch, if you have write access) and create a topic branch from an up-to-date `main`, named by intent: `fix/…`, `feat/…`, `ci/…`, `docs/…`.
2. Make one focused change, with tests and documentation in the same branch.
3. Open a pull request against `main` and fill in the five points below.
4. Wait for every required check to pass. `main` cannot be pushed to directly, force-pushed or deleted, and a pull request cannot merge while a check is failing, the branch is behind `main`, or a review thread is unresolved.
5. The maintainer merges with a merge commit, or squashes a branch whose history is noise.

The required checks are:

| Workflow | Checks |
|---|---|
| [Test](.github/workflows/test.yml) | `go` (formatting, unit and E2E tests, vet, govulncheck), `race`, `deployment-assets` (manifest policy, Compose, release image build and Trivy scan) |
| [Security](.github/workflows/security.yml) | gitleaks, gosec + Semgrep, CodeQL, OSV-Scanner + Trivy, Trivy IaC, actionlint + zizmor, ZAP DAST, IAST |

Each security gate is blocking. [docs/security-pipeline.md](docs/security-pipeline.md) explains what fails each one and how to run the dynamic gates locally (`make security-dast`, `make security-iast`). Do not silence a finding to get a green run: fix it, or justify a narrow exception in the same pull request (`#nosec <rule> -- reason`, or one rule/method/path entry in `security/dast/accepted-risks.json`).

Dependabot opens weekly update pull requests for Go modules, SHA-pinned Actions and digest-pinned base images. They go through the same checks.

## Commit and pull request quality

Use clear, imperative commit messages. A pull request should explain:

1. the problem and threat/safety impact;
2. the chosen design and rejected alternatives;
3. changed privileges, network paths, or protocol behavior;
4. how it was tested;
5. any remaining limitation or rollout requirement.

Before requesting review:

- [ ] `go test ./...`, race tests, and `go vet ./...` pass where supported.
- [ ] The Test and Security workflows are green, with any new suppression justified inline.
- [ ] Every new third-party Action, image or tool is pinned by commit SHA, digest or checksum.
- [ ] Generated/build artifacts and `.env` are not staged.
- [ ] No secret, key, kubeconfig, token, or sensitive fixture is included.
- [ ] New tool inputs/results are bounded and typed.
- [ ] RBAC remains least privilege with no wildcard expansion.
- [ ] Default behavior remains dry-run and mutation-disabled.
- [ ] Documentation distinguishes implemented behavior from target work.

Contributions are accepted under the [Apache License 2.0](LICENSE).
