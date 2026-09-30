# Local fixture demo

## What this demo proves

The fixture demo exercises the same application and transport boundaries as a cluster deployment without contacting Kubernetes:

```text
Monitor -> Investigator -> read MCP -> fixture evidence
Monitor -> signed delegation -> Operator -> action MCP -> fixture action receipt
Monitor -> read MCP -> post-action verification (successful live action only)
```

It demonstrates process composition, bounded tools, structured agent messages, grant validation, dry-run behavior, and audit correlation. The repository integration test exercises the same fixture path in-process across real MCP and A2A HTTP transports.

It does **not** prove Kubernetes RBAC, NetworkPolicy enforcement, production identity/TLS, distributed replay protection, live Victoria schemas, safe workload-specific remediation, or protocol conformance.

## Safe defaults

The checked-in Compose topology is intentionally diagnosis-only by default:

```dotenv
AEGIS_BACKEND=fixture
AEGIS_DRY_RUN=true
AEGIS_ALLOW_MUTATIONS=false
AEGIS_DELEGATION_PRIVATE_KEY=
AEGIS_DELEGATION_PUBLIC_KEY=
```

Without a keypair, Monitor may detect and investigate but cannot issue a valid action delegation. Adding keys exercises authorization; it does not turn off dry-run.

Investigator uses the deterministic heuristic reasoner unless all three optional Responses API variables (`AEGIS_LLM_BASE_URL`, `AEGIS_LLM_API_KEY`, and `AEGIS_LLM_MODEL`) are set. Provider errors fall back to the deterministic reasoner.

## Prerequisites

- Go 1.26 or newer for direct process execution
- Docker with Compose for the recommended five-process topology
- The fixture referenced by Compose at `testdata/fixtures/unavailable-deployment.json`

## Option A: Docker Compose

### 1. Prepare configuration

```bash
cp .env.example .env
```

Keep these values unchanged for the first run:

```dotenv
AEGIS_DRY_RUN=true
AEGIS_ALLOW_MUTATIONS=false
AEGIS_DELEGATION_PRIVATE_KEY=
AEGIS_DELEGATION_PUBLIC_KEY=
```

### 2. Start the topology

```bash
docker compose up --build
```

Compose maps the services only to loopback:

| Component | Local address |
|---|---|
| Monitor | `http://127.0.0.1:8081` |
| Investigator | `http://127.0.0.1:8082` |
| Operator | `http://127.0.0.1:8083` |
| Read MCP | `http://127.0.0.1:8084/mcp` |
| Action MCP | `http://127.0.0.1:8085/mcp` |

Service-to-service traffic uses container port `8080` and Compose DNS names.

Monitor begins polling automatically. Its published A2A route is not a manual scan API and rejects inbound workflow requests.

### 3. Observe diagnosis-only behavior

Follow the logs:

```bash
docker compose logs -f aegis-monitor aegis-investigator aegis-mcp-read
```

Expected safety properties:

- a fixture signal is observed and verified;
- Investigator requests only read tools;
- evidence and diagnosis share one incident/correlation context;
- no delegation is emitted because Monitor has no private key;
- action MCP performs no mutation;
- the no-key outcome is visible in the Monitor's structured JSON log.

The exact log text is not an API. Confirm structured fields and process exit status rather than matching prose.

### 4. Stop cleanly

```bash
docker compose down
```

The fixture topology has no required persistent volume. `docker compose down -v` should not be necessary.

## Option B: direct Go processes

Use one terminal per process. All commands share the fixture and safety settings but need different listen/public addresses.

Common environment:

```bash
export AEGIS_ALLOWED_NAMESPACE=outage-arena
export AEGIS_BACKEND=fixture
export AEGIS_FIXTURE_PATH=./testdata/fixtures/unavailable-deployment.json
export AEGIS_DRY_RUN=true
export AEGIS_ALLOW_MUTATIONS=false
export AEGIS_OBSERVE_MCP_URL=http://127.0.0.1:8090/mcp
export AEGIS_OPERATE_MCP_URL=http://127.0.0.1:8091/mcp
export AEGIS_INVESTIGATOR_URL=http://127.0.0.1:8081
export AEGIS_OPERATOR_URL=http://127.0.0.1:8082
```

Start in dependency order:

```bash
AEGIS_LISTEN_ADDR=:8090 AEGIS_PUBLIC_URL=http://127.0.0.1:8090 \
  go run ./cmd/aegissre mcp-server --profile=read

AEGIS_LISTEN_ADDR=:8091 AEGIS_PUBLIC_URL=http://127.0.0.1:8091 \
  go run ./cmd/aegissre mcp-server --profile=action

AEGIS_LISTEN_ADDR=:8081 AEGIS_PUBLIC_URL=http://127.0.0.1:8081 \
  go run ./cmd/aegissre investigator

AEGIS_LISTEN_ADDR=:8082 AEGIS_PUBLIC_URL=http://127.0.0.1:8082 \
  go run ./cmd/aegissre operator

AEGIS_LISTEN_ADDR=:8080 AEGIS_PUBLIC_URL=http://127.0.0.1:8080 \
  go run ./cmd/aegissre monitor
```

These examples use POSIX shell syntax. In PowerShell, set the corresponding `$env:NAME` values in each terminal before running the same `go run` commands.

## Exercise signed delegation safely

Generate a disposable development keypair:

```bash
go run ./cmd/aegissre keygen
```

Copy the emitted values into the untracked `.env` file:

```dotenv
AEGIS_DELEGATION_PRIVATE_KEY=<generated private value>
AEGIS_DELEGATION_PUBLIC_KEY=<generated public value>
AEGIS_DELEGATION_KEY_ID=aegissre-monitor-v1
AEGIS_DRY_RUN=true
AEGIS_ALLOW_MUTATIONS=false
```

Restart Compose:

```bash
docker compose up --build
```

Now expect the delegation path to run, while the action remains a fixture/dry-run. Confirm:

1. the grant is bound to one incident, diagnosis digest, audience, action, target, and expiry;
2. Operator verifies it;
3. action MCP verifies it independently;
4. the receipt says dry-run/no persistent side effect;
5. a replay returns a cached/recovered result or a denial rather than performing a second action;
6. Monitor escalates the dry-run outcome without inferring recovery; only a successful live action triggers immediate post-action observation, followed by scheduled read-only observations if verification remains pending.

Delete the disposable keys from `.env` after the exercise. Never use demo keys in k3s.

## Negative cases

These cases are more important than the happy path. Exercise them through tests or fixture inputs supported by the current revision:

| Case | Expected result |
|---|---|
| No private key | Diagnosis only; no grant |
| Changed grant byte | Bad signature; no action |
| Expired or not-yet-valid grant | Denied by both verifiers |
| Wrong audience | Denied |
| Namespace other than `outage-arena` | Denied before backend call |
| Action/parameters differ from grant | Denied |
| Scale request equal to or below signed expected replicas | Denied; autonomous scale must strictly increase replicas |
| Reused grant ID | Cached/recovered result or replay denial; no second mutation |
| Changed resource precondition | Conflict; request a new investigation |
| Read MCP unavailable during detection | Detection fails and is retried on the next interval; no new candidate incident is queued |
| Action MCP unavailable after grant | Incident becomes failed and the fingerprint enters cooldown; action result may require manual verification |
| Verification remains unhealthy or unreadable | Same incident remains `verification_pending` and blocks redelegation; scheduled scans retry observation only, then escalate it when the cooldown-length window expires |

## Inspect the MCP catalog

The authoritative catalog is the result of MCP `tools/list`. The read server exposes:

```text
metrics_query_template
logs_search
k8s_get_workload_snapshot
k8s_get_pod_logs
```

The action server exposes:

```text
k8s_execute_remediation
k8s_get_remediation_status
```

Use an MCP 2026-07-28-capable client. Do not substitute ad hoc `curl` examples that omit required protocol discovery/version/method headers and then treat a transport rejection as an application failure.

## Success criteria

The fixture demo is successful when:

- all five processes start with validated configuration;
- tool discovery shows only the catalog for each privilege plane;
- a deterministic incident produces bounded evidence and a sealed diagnosis;
- no-key mode stops before delegation;
- keyed mode validates the same grant twice;
- dry-run remains non-mutating;
- audit events correlate one incident without exposing key material;
- dry-run does not infer recovery, and the fixture remains unchanged;
- all processes stop cleanly.

The automated integration check for the transport-spanning dry-run path is:

```bash
go test ./internal/integration -run TestFixtureIncidentFlowsAcrossMCPAndA2A
```

Passing this test does not validate Docker networking, a deployed cluster, live Victoria schemas, Kubernetes RBAC/NetworkPolicy enforcement, or production identity.
