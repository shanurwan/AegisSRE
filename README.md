# AegisSRE

Autonomous reliability with bounded authority.

AegisSRE is a three-agent reliability system for Kubernetes. Monitor detects and verifies incidents across metrics, logs, and traces; Investigator builds an evidence-backed diagnosis and exact action proposal; Operator performs only a narrowly delegated action, returns its receipt for independent verification, then creates the terminal incident report and can deliver it through WhatsApp. Agents coordinate over the official [Agent2Agent (A2A) Protocol v1.0](https://a2a-protocol.org/v1.0.0/specification); tools are exposed over the official [Model Context Protocol (MCP) 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) using stateless Streamable HTTP.

The safety boundary is deliberate: diagnosis does not imply permission, and permission does not imply execution. Live mutations require a short-lived, incident-bound Ed25519 delegation that both Operator and the action MCP server validate independently. Dry-run is the default.

> **Project status:** pre-release. The executable, three agent services, two MCP profiles, fixture/Victoria/Kubernetes adapters, A2A/MCP transports, terminal reporting, opt-in WhatsApp adapter, Compose topology, and Kustomize manifests are implemented. Deterministic control-plane E2E tests cross real MCP, A2A, and notification HTTP boundaries for both a signed live fixture recovery and an outside-authority escalation; the default dry-run path is tested separately. This is not a separate-process or live-k3s E2E claim. Live k3s telemetry schemas, WhatsApp credentials/templates and egress, independent protocol conformance, durable shared incident/replay/report state, authenticated transport and TLS, key rotation, OTLP export, and workload-specific policy remain to be implemented or validated before use.

## System shape

```text
                       AegisSRE
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
       Monitor         Investigator       Operator
    detect / verify      diagnose        remediate
          │                │                │
          └──────── A2A v1.0 ───────────────┘
                           │
               constrained MCP tools
                    ┌──────┴──────┐
                    ▼             ▼
              Observe plane   Action plane
               read-only       delegated
                    │             │
                    └──────┬──────┘
                           ▼
                Kubernetes / telemetry
```

| Component | Responsibility | Authority |
|---|---|---|
| Monitor | Detects metric/log/trace candidates, verifies them, requests investigation, evaluates the result, issues a bounded grant, and independently verifies recovery | Read-only evidence plus the grant-signing key; no Kubernetes write credential |
| Investigator | Collects bounded multi-signal evidence and returns a diagnosis with confidence, supporting evidence, and an exact proposed action | Observe MCP only; cannot sign a grant or mutate infrastructure |
| Operator | Validates a grant, requests the exact authorized action, returns its receipt, and creates/notifies a sanitized report for Monitor-declared terminal states | Action MCP client and optional WhatsApp token; no direct Kubernetes credential |
| Observe MCP | Provides allowlisted metric, log, and trace templates plus workload snapshots and bounded pod logs | Read-only telemetry and Kubernetes access |
| Action MCP | Revalidates the grant and performs one allowlisted operation | Minimal namespace-scoped Kubernetes write access |

The two MCP planes must be independently addressable and independently authorized. Combining their credentials defeats the privilege boundary even if they share a binary or container image.

Monitor is schedule-driven: it scans immediately at startup and then every `AEGIS_SCAN_INTERVAL`, requiring `AEGIS_VERIFICATION_COUNT` consecutive qualifying scans before investigation. Its Agent Card and `/a2a` route are published, but the current handler rejects every inbound workflow request; there is no webhook, alert bridge, or other external Monitor trigger.

## Protocol contracts

- **A2A v1.0:** Agent Cards advertise the three roles; tasks, messages, and structured data parts carry incident requests, evidence, diagnoses, delegation envelopes, and receipts. Requests use protocol version `1.0` rather than an SDK version number.
- **MCP 2026-07-28:** stateless Streamable HTTP at `/mcp`. Requests carry the negotiated protocol version and routable method/name headers required by the specification. No long-lived MCP session is part of the security design.
- **Runtime telemetry:** every process serves `/healthz`, a shallow `/readyz`, and Prometheus process/build metrics at `/metrics`. OTLP export is not wired; the checked-in local and Kubernetes configurations supply neither OTEL settings nor collector egress.

SDK versions are pinned in [`go.mod`](go.mod). Protocol conformance is a separate claim and must be demonstrated by tests; importing an SDK alone is not evidence of conformance.

## Tool surface

The typed contracts live under `internal/toolapi`. The initial bounded catalog is:

**Observe plane**

- `metrics_query_template` — selects a server-owned metric template; callers cannot submit arbitrary PromQL.
- `logs_query_template` — counts only server-owned, five-minute structured-log signals grouped by an exact namespace/workload identity.
- `traces_query_template` — counts only server-owned, five-minute trace signals grouped by an exact namespace/workload identity.
- `logs_search` — searches within namespace, lookback, and result-size limits.
- `k8s_get_workload_snapshot` — returns a bounded workload, pod, and event snapshot.
- `k8s_get_pod_logs` — returns capped current or previous container logs.

**Action plane**

- `k8s_execute_remediation` — accepts a signed grant and an explicit dry-run request.
- `k8s_get_remediation_status` — verifies whether the grant's intended state has been reached.

There is intentionally no raw shell, `exec`, arbitrary query, generic patch, generic manifest apply, secret read, or unconstrained delete tool.

## Investigator reasoning

Investigator uses the deterministic heuristic reasoner by default. Setting all three of `AEGIS_LLM_BASE_URL`, `AEGIS_LLM_API_KEY`, and `AEGIS_LLM_MODEL` enables the optional Responses API reasoner as the primary. Provider errors, invalid responses, and rejected structured output fall back to the deterministic reasoner; a valid but inconclusive provider diagnosis is preserved rather than replaced.

Model output remains untrusted. The adapter uses a strict JSON schema, accepts only evidence IDs gathered by the current investigation, and binds every proposal to the trusted target supplied by Monitor. Raw payloads from `logs_search` and `k8s_get_pod_logs` never enter the external prompt: only their provenance metadata and a fixed redaction marker are projected, while the original sealed evidence remains available to the local deterministic reasoner. In Kubernetes, the base NetworkPolicy blocks external model egress. Enabling a provider therefore also requires an explicit, narrowly scoped egress overlay; none is included by default.

## Quick start

Prerequisites:

- Go 1.26 or a compatible newer toolchain
- Docker with Compose for the multi-process demo
- No Kubernetes cluster is required for fixture mode

```bash
git clone https://github.com/shanurwan/AegisSRE.git
cd AegisSRE
cp .env.example .env
go test ./...
make test-e2e
```

The command surface is one binary with the following service modes:

```bash
go run ./cmd/aegissre mcp-server --profile=read
go run ./cmd/aegissre mcp-server --profile=action
go run ./cmd/aegissre investigator
go run ./cmd/aegissre operator
go run ./cmd/aegissre monitor
```

Run both MCP profiles before the agents. Keep `AEGIS_DRY_RUN=true` and `AEGIS_ALLOW_MUTATIONS=false` for local work. Use `go run ./cmd/aegissre --help` and the current source as the authoritative command-availability check.

The equivalent multi-process startup is:

```bash
docker compose up --build
```

See [the demo guide](docs/demo.md) for the implemented fixture workflow and its validation limits.

## Outage Arena integration

The target k3s environment exposes these telemetry endpoints:

| Signal | In-cluster endpoint | Notes |
|---|---|---|
| Metrics | `http://vmsingle.observability.svc.cluster.local:8428` | VictoriaMetrics; Prometheus-compatible query API, 30-day retention in the current arena configuration |
| Logs | `http://vlogs.observability.svc.cluster.local:9428` | VictoriaLogs; cluster pod logs, 14-day retention |
| Traces | `http://vtraces.observability.svc.cluster.local:10428` | VictoriaTraces; AegisSRE appends the bounded LogsQL stats API path, 7-day retention |
| OTLP | `http://otel-collector.observability.svc.cluster.local:4318` | HTTP OTLP ingress; gRPC is available on port `4317` |

The read MCP consumes VictoriaMetrics, VictoriaLogs, and VictoriaTraces. Log detection requires the canonical `aegissre.io/workload` pod label in the collected stream, and trace detection requires `k8s.namespace.name` plus `k8s.deployment.name` resource attributes. Missing or mismatched identity fails closed. The arena's current collector does not add those trace attributes, so validate/enrich its OTEL pipeline before relying on trace incidents. AegisSRE's own OTLP export is not wired.

The arena currently has no workload scenarios or alert rules under `apps/laboratory`; AegisSRE must not imply otherwise. Deployment also requires infra-owned read RBAC for cluster evidence and a separate, minimal action Role in `outage-arena`. Details are in [deployment](docs/deployment.md).

## Safety defaults

- Dry-run is on unless explicitly disabled.
- Live Operator execution is separately disabled by default.
- Log- and trace-triggered incidents are detected and investigated, but cannot authorize a live mutation unless `AEGIS_ALLOW_LOG_TRACE_ACTIONS=true`; keep it false until workload identity is collector-owned and verified.
- Only allowlisted namespaces, actions, metric/log/trace templates, and bounded log searches are accepted.
- Grants are incident-bound, audience-bound, exact-parameter-bound, short-lived, and replay-protected.
- `AEGIS_DELEGATION_KEY_ID` must identify the same key on Monitor, Operator, and action MCP; the default is `aegissre-monitor-v1`.
- A scale request must strictly increase the signed expected replica count; no-op scaling and scale-down are denied. Defaults cap the request at 20 total replicas and the increase at 5, controlled by `AEGIS_MAX_SCALE_REPLICAS` and `AEGIS_MAX_SCALE_INCREASE`.
- Operator and action MCP validate every grant independently.
- Investigator defines the bounded action intent; only Monitor delegates authority. A proposal alone can never reach the action MCP.
- Monitor authorizes every terminal report request with a distinct, short-lived Ed25519 signature; Operator verifies it before report creation or notification, so an A2A sender claim alone cannot trigger WhatsApp.
- Every resolved, escalated, or failed terminal outcome is eligible for a non-authoritative Operator report, including rejected actions, validated action failures, and action outcomes that could not be verified. Ambiguous post-delegation outcomes escalate instead of being mislabeled as failures. WhatsApp delivery status is separate from incident state, so notification failure cannot rewrite the reliability result.
- The Monitor signing key is never mounted in Investigator, Operator, or either Kubernetes tool plane.
- Implemented investigation, authorization, and action paths emit structured audit events to JSON process logs; a durable append-only audit sink and full decision coverage remain production work.
- Before delegation, a fresh healthy snapshot resolves the incident without action. After a successful live action, Monitor observes immediately; if the target is not yet healthy, the same incident remains `verification_pending` and scheduled scans retry observation without retrying the action. It resolves on recovery or escalates when the `AEGIS_INCIDENT_COOLDOWN` verification window elapses.

Read the complete [security model](docs/security-model.md) before enabling a write path.

## Repository guide

```text
cmd/aegissre/             process composition and CLI modes
internal/core/            domain model and ports
internal/app/             Monitor, Investigator, and Operator use cases
internal/transport/       A2A and MCP protocol adapters
internal/adapters/        backend, telemetry, Kubernetes, fixture, and reasoner adapters
internal/security/        delegation signing and authorization policy
internal/platform/        configuration, audit logging, HTTP clients, and runtime utilities
docs/                     design, deployment, demo, and operations
```

The dependency rule points inward: domain and application code must not import HTTP, A2A, MCP, Kubernetes, Victoria, or vendor SDK types. Those types terminate in adapters.

## Documentation

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Deployment](docs/deployment.md)
- [Local demo](docs/demo.md)
- [Operations runbook](docs/runbook.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## Non-goals

AegisSRE is not:

- a replacement for alerting, paging, GitOps, admission control, or human incident command;
- a general-purpose `kubectl` proxy;
- a system that lets an LLM hold cluster-admin credentials;
- permission to make an action more powerful because a diagnosis sounds confident;
- production-ready merely because the fixture demo completes.

## License

Licensed under the [Apache License 2.0](LICENSE).
