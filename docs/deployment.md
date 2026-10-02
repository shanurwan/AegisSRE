# Deployment

## Status and scope

This guide covers the base, production-scaffold, and `laboratory` Kustomize overlays for the k3s `outage-arena` namespace. The production overlay adds strict mTLS, exact workload policy, PostgreSQL control state, OTLP egress, migration orchestration, role-separated Secret projections, and tighter NetworkPolicies. It is intentionally non-deployable until its zero image digest and `replace-before-live` target are replaced. The laboratory overlay binds policy and RBAC to one canary. Their presence is not evidence that an image has been published, secrets/database have been provisioned, manifests have been applied, or the gated live acceptance has passed.

Keep the first cluster deployment read-only. Enable action MCP in dry-run, inspect the resulting policy decisions and receipts, and introduce a narrowly scoped mutation only after the checklist at the end of this document passes.

## Existing platform

The outage-arena infrastructure provides:

- a single-node k3s cluster named `laboratory`;
- Flux with multi-tenant reconciliation;
- the `outage-arena` application namespace;
- VictoriaMetrics, VictoriaLogs, VictoriaTraces, and an OpenTelemetry collector in `observability`;
- Envoy Gateway and Cloudflare Tunnel for explicitly routed public services;
- Harbor for container images;
- Teleport access through `tsh kube login laboratory`.

The lab tenant is namespaced. Its Flux identity can manage applications in `outage-arena`, but it has no general cluster-scoped permissions or cross-namespace reference grants.

## Deployment topology

Use one immutable image with a different command and identity per workload:

| Workload | Command | Kubernetes credential | Network reachability |
|---|---|---|---|
| `aegis-monitor` | `aegissre monitor` | none | Investigator, Operator, observe MCP |
| `aegis-investigator` | `aegissre investigator` | none | Observe MCP; external model only with an explicit overlay |
| `aegis-operator` | `aegissre operator` | none | Action MCP; WhatsApp only through reviewed egress when enabled |
| `aegis-mcp-read` | `aegissre mcp-server --profile=read` | read-only ServiceAccount | Kubernetes API, VictoriaMetrics, VictoriaLogs, VictoriaTraces |
| `aegis-mcp-action` | `aegissre mcp-server --profile=action` | minimal write ServiceAccount | Kubernetes API |

The local/base topology listens on plaintext `:8080`. The production/laboratory overlays instead expose only mTLS application traffic on `:8443`; Kubernetes probes and metrics use an unexposed health-only listener on `:9090`. Give every workload a ClusterIP Service and do not expose agent or MCP endpoints through a public Gateway.

Every process propagates W3C trace context. The production overlay configures bounded OTLP/HTTP trace export to the in-cluster collector and grants egress only to its exact namespace/workload labels. `/metrics` exposes Prometheus process/build metrics. JSON stdout remains the single application-log path.

Running both MCP profiles in one pod is acceptable only for a local fixture. In Kubernetes it would collapse the credential and network boundaries.

## GitOps integration

The existing lab source in the outage-arena infrastructure repository uses sparse checkout of `apps/laboratory` from that repository. It does not automatically watch AegisSRE.

Use one of these reviewed approaches:

1. **Release reference in outage-arena:** publish an immutable AegisSRE image, then add the Deployments, Services, configuration, and namespace-local RBAC under `outage-arena/apps/laboratory`.
2. **Dedicated source:** add a namespaced GitRepository or OCIRepository in `lab`, then a child Flux Kustomization that targets `outage-arena` and runs as `lab-reconciler`.

The second approach still cannot create cluster-scoped read RBAC. Any ClusterRole/ClusterRoleBinding or cross-namespace RoleBinding belongs in the infra/project boundary and needs separate review.

Pin an image digest for reproducible incidents. Do not deploy `latest` or grant Flux image automation permission until the release policy is defined.

## Configuration

Set these values per workload. Defaults shown here reflect the application configuration, but production manifests should make safety-critical values explicit.

| Variable | Typical cluster value | Consumers |
|---|---|---|
| `AEGIS_LISTEN_ADDR` | `:8443` | all application listeners in production |
| `AEGIS_ADMIN_LISTEN_ADDR` | `:9090`; must differ from application listener | all in mTLS mode |
| `AEGIS_PUBLIC_URL` | workload Service URL | all A2A-serving agents |
| `AEGIS_LOG_LEVEL` | `info` | all |
| `AEGIS_ALLOWED_NAMESPACE` | `outage-arena` | all; enforce again in both MCP planes |
| `AEGIS_OBSERVE_MCP_URL` | `https://aegis-mcp-read:8443/mcp` | Monitor, Investigator |
| `AEGIS_OPERATE_MCP_URL` | `https://aegis-mcp-action:8443/mcp` | Operator |
| `AEGIS_INVESTIGATOR_URL` | `https://aegis-investigator:8443` | Monitor |
| `AEGIS_OPERATOR_URL` | `https://aegis-operator:8443` | Monitor |
| `AEGIS_VICTORIA_METRICS_URL` | `http://vmsingle.observability.svc.cluster.local:8428` | read MCP |
| `AEGIS_VICTORIA_LOGS_URL` | `http://vlogs.observability.svc.cluster.local:9428` | read MCP |
| `AEGIS_VICTORIA_TRACES_URL` | `http://vtraces.observability.svc.cluster.local:10428` | read MCP |
| `AEGIS_BACKEND` | `kubernetes` | MCP profiles |
| `AEGIS_SCAN_INTERVAL` | begin conservatively, e.g. `30s` | Monitor |
| `AEGIS_VERIFICATION_COUNT` | `2` or more | Monitor |
| `AEGIS_INCIDENT_COOLDOWN` | `15m` in the checked-in base; bounds pending verification and later fingerprint suppression | Monitor |
| `AEGIS_REQUEST_TIMEOUT` | `10s` | all clients/servers |
| `AEGIS_EVIDENCE_BUDGET` | bounded integer, default `6` | Investigator |
| `AEGIS_MAX_LOG_BYTES` | bounded integer, default `32768` | read MCP/Investigator |
| `AEGIS_DELEGATION_TTL` | `2m`; maximum `5m` | Monitor and verifiers |
| `AEGIS_DELEGATION_KEY_ID` | `aegissre-monitor-v1` | Monitor, Operator, action MCP; must match |
| `AEGIS_MAX_SCALE_REPLICAS` | default `20`; validated range `1..1000` | Monitor, Operator, action MCP |
| `AEGIS_MAX_SCALE_INCREASE` | default `5`; validated range `1..AEGIS_MAX_SCALE_REPLICAS` | Monitor, Operator, action MCP |
| `AEGIS_DRY_RUN` | `true` | Monitor, Operator, action MCP |
| `AEGIS_ALLOW_MUTATIONS` | `false` | action MCP |
| `AEGIS_ALLOW_LOG_TRACE_ACTIONS` | `false`; enable only after collector-owned workload identity is proven | Monitor |
| `AEGIS_WORKLOAD_POLICY_FILE` | `/etc/aegissre/policy/policy.json`; required for authenticated production control-plane configuration | Monitor, Operator, read MCP, action MCP |
| `AEGIS_MTLS_ENABLED` | `true`; required for live action configuration | all |
| `AEGIS_TLS_CERT_FILE`, `AEGIS_TLS_KEY_FILE`, `AEGIS_TLS_CA_FILE` | read-only projected files | all |
| `AEGIS_TLS_IDENTITY` | exact sole URI SAN for that ServiceAccount | all |
| `AEGIS_TRUST_DOMAIN`, `AEGIS_SYSTEM_NAMESPACE` | `aegissre.internal`, `outage-arena` in current overlay | all |
| `AEGIS_DATABASE_URL_FILE` | projected role-specific connection string | Monitor, Operator, action MCP, migration Job |
| `AEGIS_DATABASE_MAX_CONNECTIONS` | `8` runtime, `2` migration | database consumers |
| `AEGIS_STATE_LEASE` | `1m`; must exceed Monitor's `30s` scan interval. For durable Operator and action MCP it must exceed `AEGIS_REQUEST_TIMEOUT` by more than `10s`, so the bounded request and post-cancellation persistence windows fit inside one lease; this also covers Operator's outbox delivery window | Monitor, Operator, action MCP/outbox leases |
| `AEGIS_INSTANCE_ID` | Pod name via downward API | Monitor, Operator, action MCP |
| `AEGIS_OUTBOX_POLL_INTERVAL` | `2s` | Operator |
| `AEGIS_OUTBOX_MAX_ATTEMPTS` | `8` | Operator |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | collector `/v1/traces` endpoint | all |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | all |
| `AEGIS_TRACE_SAMPLE_RATIO` | `0.1` | all |
| `AEGIS_WHATSAPP_ENABLED` | `false`; opt in only after Secret and restricted egress are ready | Operator |
The checked-in base explicitly pins both scale limits to the defaults. Keep the same values on Monitor, Operator, and action MCP so policy cannot disagree across verification boundaries.

The Monitor private key and Operator public key also authorize and verify terminal report requests under a signature domain distinct from action grants. WhatsApp cannot operate safely without this key relationship; an A2A `sender` field is not authentication.

### Optional WhatsApp incident reports

Operator creates a sealed, sanitized report only after Monitor sends a terminal `incident.report.request`. It sends an approved WhatsApp template when `AEGIS_WHATSAPP_ENABLED=true`; replies are informational and never authorize an action. Configure only Operator:

- `AEGIS_WHATSAPP_ENABLED`: explicit opt-in gate, default `false`;
- `AEGIS_WHATSAPP_GRAPH_VERSION`: an explicitly pinned Graph API version supported by the Meta app;
- `AEGIS_WHATSAPP_PHONE_NUMBER_ID`: Secret-backed sender phone-number ID;
- `AEGIS_WHATSAPP_ACCESS_TOKEN`: Secret-backed, minimally scoped System User token with `whatsapp_business_messaging`;
- `AEGIS_WHATSAPP_RECIPIENT`: Secret-backed destination digits without `+`;
- `AEGIS_WHATSAPP_TEMPLATE`: approved template name containing one body variable;
- `AEGIS_WHATSAPP_LANGUAGE`: approved template locale, default `en_US`;

The checked-in `aegis-whatsapp` Secret references are optional, and [`whatsapp-secret.example.yaml`](../deploy/kubernetes/base/whatsapp-secret.example.yaml) is deliberately excluded from Kustomize. The base and production scaffold keep delivery disabled and give Operator no Internet egress. Standard Kubernetes NetworkPolicy cannot safely express a DNS-name allowlist for `graph.facebook.com`; route Operator through a platform-owned egress proxy/gateway restricted to that host and port 443, then add only the namespace/pod-to-proxy rule. Do not add `0.0.0.0/0:443`.

Enabling WhatsApp requires PostgreSQL. Operator atomically commits the signed report request, sealed report, and one outbox row before returning `queued`; a leased worker owns bounded retry and dead-letter transitions. The runtime claims one row per worker iteration, gives each provider call an explicit deadline, and refuses a lease too short to cover the entire claimed delivery window plus acknowledgement headroom. Delivery is still at-least-once because Meta acceptance and the PostgreSQL acknowledgement cannot share a transaction. A crash in that interval can duplicate a template message, so the approved template must be safe to receive more than once. Notification failure remains separate from incident state.

### Optional reasoner

Investigator uses its deterministic heuristic reasoner when `AEGIS_LLM_BASE_URL` is empty. To enable the optional Responses API primary, configure all three variables only on Investigator:

- `AEGIS_LLM_BASE_URL`: HTTP(S) API base URL, such as an API `/v1` base; the adapter appends `/responses`;
- `AEGIS_LLM_API_KEY`: Secret-backed bearer credential;
- `AEGIS_LLM_MODEL`: provider model identifier.

Configuration fails if the base URL is set without both the key and model. If the provider request or structured response fails, Investigator uses the deterministic reasoner; a successful but inconclusive provider report is not replaced.

The checked-in base NetworkPolicies do not grant Investigator egress to an external model endpoint. Merely setting the three variables cannot bypass that default deny. Enabling a provider requires an explicit, narrowly scoped deployment overlay containing the reviewed egress policy in addition to the configuration and Secret; no external-model overlay is checked in.

## Delegation keys

Generate keys with the project binary in a trusted local environment:

```bash
go run ./cmd/aegissre keygen
```

Handle the output as secret material:

- `AEGIS_DELEGATION_PRIVATE_KEY_FILE`: Monitor-only file containing the active private key.
- `AEGIS_DELEGATION_PUBLIC_KEYRING_FILE`: strict `v1` JSON keyring mounted in Operator and action MCP.
- `AEGIS_DELEGATION_KEY_ID`: Monitor's active non-secret signing-key ID; `keygen` emits the default `aegissre-monitor-v1`.
- read MCP and Investigator receive neither key.

Create the Kubernetes Secret out of band or through the cluster's approved secret manager. Do not put key values in this repository, a Kustomization, a shell history, a ticket, or a screenshot.

The verifier file shape is strict and versioned:

```json
{
  "version": "v1",
  "keys": [
    {"key_id": "aegissre-monitor-v1", "public_key": "<base64-ed25519-public-key>"}
  ]
}
```

When no private key is configured, Monitor remains capable of detection and diagnosis but does not delegate an action.

Use overlapping trust for rotation: distribute a keyring containing old and new public keys, switch Monitor to the new private key/ID only after both verifiers have the ring, wait past the maximum signed-object lifetime and rollout convergence, then remove the old public key. Unknown and retired IDs are rejected; verifiers never try a different key as fallback.

## Workload mTLS

The production overlay expects five leaf-key Secrets plus a separate CA-bundle Secret. Each leaf certificate must have both client-auth and server-auth extended usage, the Service DNS names needed for normal HTTPS verification, and exactly one URI SAN:

```text
spiffe://aegissre.internal/ns/outage-arena/sa/<service-account>
```

The URI is an internal workload-identity format; the repository does not deploy a SPIFFE control plane. `AEGIS_TLS_IDENTITY` must exactly match the local leaf. Servers require and verify client certificates; clients validate the CA chain, DNS name, and exact expected peer URI. The application handler then enforces the fixed role graph before parsing protocol bodies. Rotate a CA by distributing an overlapping trust bundle before replacing leaves and remove the retired CA only after rollout convergence.

The admin listener contains only `/healthz`, `/readyz`, and `/metrics`. Do not expose port `9090` through a Service or ingress. Protect node/pod access through the cluster's ordinary administrative controls.

## Exact workload policy

The mounted `aegissre.io/workload-policy/v1` document contains only exact `apps/v1` Deployment targets, allowed action kinds, allowed incident signal sources, and scale bounds. Monitor, Operator, read MCP, and action MCP must consume the same generated ConfigMap. The effective normalized digest is signed into every delegation, so drift between decision points stops execution. Live configuration fails without a policy file.

Use the checked-in [production policy sentinel](../deploy/kubernetes/overlays/production/workload-policy.json) as the schema example, not as authorization. Release review must replace the sentinel target and assign a new meaningful `policy_id` whenever effective authority changes.

Keep the Kubernetes Roles at least as narrow as the document. The production scaffold uses `replace-before-live` in both places to make accidental deployment fail; the laboratory overlay replaces it with only `aegissre-e2e-canary`, allows only `restart_deployment`, and permits only metric-triggered autonomous action.

## PostgreSQL control state and migrations

PostgreSQL is required for live Monitor/Operator/action-MCP operation and for WhatsApp. It stores a fenced Monitor checkpoint, two separately scoped execution ledgers, receipts/uncertain outcomes, append-only audit events, sealed reports, and the notification outbox. It does not store raw platform telemetry and is not a substitute for a historical incident system.

Run migrations before runtime rollout:

```bash
AEGIS_DATABASE_URL='postgresql://...?sslmode=verify-full&sslrootcert=/path/to/ca.crt' aegissre migrate
```

The migration command always requires hostname-verifying PostgreSQL TLS; local
plaintext or `sslmode=require` connections are rejected just like authenticated
runtime connections.

The production overlay supplies a one-shot migration Job; release automation must replace its sentinel name with a unique immutable release ID and wait for completion. Migrations are embedded, forward-only, serialized by a PostgreSQL advisory lock, and checksummed. Runtime processes have no DDL requirement: at startup and readiness they verify every expected version/checksum and fail closed on an absent, stale, or modified schema.

Provision at least four separate connection Secrets/roles:

| Role | Required responsibility |
|---|---|
| migration | own/apply schema changes; never mounted in runtime pods |
| Monitor runtime | lease/checkpoint read/write only |
| Operator runtime | Operator execution scope, incident report/outbox, and append-only audit surface |
| action MCP runtime | action-MCP execution scope and append-only audit surface |

The checked-in Secret projections expect TLS-verified URLs pointing at `aegis-postgres-rw.aegissre-data.svc.cluster.local:5432` with the CA at `/var/run/secrets/aegissre/database/ca.crt`. A database/platform owner must apply and review the runtime grants separately; embedded migrations create schema objects but do not create login roles. The repository intentionally does not deploy PostgreSQL, create roles/grants, configure backups, or run retention cleanup. Use an external HA service, test restore, monitor replication/storage, and define cleanup for completed execution/outbox rows before production.

Migration `000003` adds dual-scope terminal-report fences and immutable `notification_requested` metadata (including backfill from existing outbox rows). Report-request signatures and durable Monitor checkpoints are v2 because they include stable `ReportCreatedAt`; this pre-release upgrade requires a fresh checkpoint or a drained v1 workflow before rollout. Schedule bounded execution cleanup after the 90-day safety horizon; it removes reported completions, terminal uncertainty, and expired fences, and its database-time cap prevents a future cutoff from shortening that horizon.

## Kubernetes RBAC

### Read plane

Create a dedicated ServiceAccount for `aegis-mcp-read`. The current Kubernetes adapter's implemented calls require this namespaced surface:

```text
pods:                    get, list
pods/log:                get
deployments:             get
replicasets:             get
events (core API):       list
```

The checked-in read Role matches those calls, including `get` on `pods/log` separately from Pod objects. Production/laboratory overlays bind Deployment reads to the exact authorized `resourceNames`. Pod and rollout-generated ReplicaSet names cannot be pre-enumerated, so read MCP authorizes every pod-log request by resolving the live Pod -> ReplicaSet -> Deployment controller chain and verifying both owner UIDs before matching the exact policy target. Labels and caller-supplied names are not authority. Validate pod-log access with `kubectl auth can-i get pods/log --as=system:serviceaccount:outage-arena:aegis-mcp-read -n outage-arena`; treat a denial as deployment drift or binding failure, not a reason to grant a broader role.

If cluster/node evidence is later required, add each resource deliberately through infra-owned RBAC. Telemetry HTTP access does not require Kubernetes RBAC, but NetworkPolicy must permit egress to the `observability` services.

### Action plane

Create a different ServiceAccount for `aegis-mcp-action`. The current Kubernetes adapter reads and merge-patches the named Deployment for both restart and scale, so its implemented API surface needs:

```text
deployments:             get, patch
```

The checked-in action Role matches this exact `get`/`patch` surface. It does not grant `list`, `watch`, or access to the `deployments/scale` subresource.

Do not grant wildcard verbs/resources, Secrets, pods/exec, ServiceAccounts, RBAC objects, token requests, persistent volumes, nodes, or custom resources unless a new typed action and threat review explicitly require them.

Agent Deployments should set `automountServiceAccountToken: false`.

## Network policy

Start from default deny. Permit only this matrix:

| Source | Destination | Reason |
|---|---|---|
| Monitor | read MCP | detection and verification |
| Monitor | Investigator | A2A diagnosis task |
| Monitor | Operator | A2A delegated action task and non-authoritative terminal report request |
| Investigator | read MCP | evidence collection |
| Operator | action MCP | exact remediation call/status |
| read MCP | Kubernetes API | bounded object reads/pod logs |
| read MCP | VictoriaMetrics/VictoriaLogs/VictoriaTraces | bounded signal queries |
| action MCP | Kubernetes API | allowlisted mutations/status |
| all five application workloads | exact in-cluster OTLP collector | trace export only, TCP 4318 |
| Monitor, Operator, action MCP, migration Job | exact external PostgreSQL pod selector | durable control state/migration, TCP 5432 |
| Investigator | approved model endpoint | not allowed by base; only through an explicit reviewed overlay |
| Operator | approved WhatsApp egress proxy | not allowed by base; only when reporting is explicitly enabled |

The production policies intersect namespace and pod selectors for CoreDNS, Victoria backends, the OTLP collector, and PostgreSQL; a label drift fails closed. They deliberately block external model and WhatsApp egress. Deny direct Operator-to-Kubernetes and Investigator-to-action-MCP traffic even if application policy would reject it. Standard NetworkPolicy behavior and enforcement depend on the target CNI, so validate this matrix live before enabling mutations.

There is intentionally no ingress rule for Monitor. It self-polls on `AEGIS_SCAN_INTERVAL`, and its current A2A handler rejects inbound workflow requests. Do not add an alert bridge or webhook ingress until an authenticated, authorized, replay-safe trigger is implemented and reviewed.

## Resource and availability guidance

Begin with one replica per component for the first rollout. PostgreSQL provides fenced Monitor single-writer leadership, scoped execution leases, receipt recovery, and outbox claims, but the checked-in production scaffold deliberately uses `Recreate` while live failover behavior is being validated. Increase replicas only after database capacity, lease timing, disruption behavior, and the gated restart/recovery scenarios have been exercised in the target cluster.

Set:

- a non-root user, read-only root filesystem, dropped Linux capabilities, and seccomp `RuntimeDefault`;
- CPU/memory requests and limits after fixture/load measurements;
- startup/readiness/liveness probes on admin-port `/healthz` and `/readyz`; database consumers return not-ready if PostgreSQL cannot be pinged or the embedded schema version/checksums do not match;
- graceful termination long enough to finish or cancel an in-flight bounded request;
- PodDisruptionBudgets only after multi-replica state semantics exist.

The HTTP readiness check does not prove Victoria, Kubernetes, Meta, or every downstream agent is healthy. Alert separately on those dependencies and on execution `uncertain`, outbox `dead_letter`, lease loss, migration failure, and database saturation.

## Access and rollout

Authenticate to the cluster:

```bash
tsh kube login laboratory
kubectl get nodes
kubectl -n outage-arena get deploy,po,svc
```

Recommended rollout order:

1. read MCP with read-only RBAC;
2. Investigator;
3. Monitor with no private signing key;
4. validate detection and diagnosis against a safe fixture/workload;
5. action MCP with `AEGIS_DRY_RUN=true`, `AEGIS_ALLOW_MUTATIONS=false`;
6. Operator and public-key distribution;
7. Monitor private key, still in dry-run;
8. only after review, enable one exact live action on one test workload.

Render and policy-check every production-shaped overlay before integrating it into Flux:

```bash
kubectl kustomize deploy/kubernetes/overlays/dry-run
kubectl kustomize deploy/kubernetes/overlays/production
kubectl kustomize deploy/kubernetes/overlays/laboratory
kubectl kustomize deploy/kubernetes/overlays/laboratory/execute
make manifest-policy-overlays
```

The production policy check expects its deliberate sentinels. A release render must instead pass `scripts/manifest-policy.py --profile release` with `--expected-image` set to the exact repository and digest that passed the two-platform image scan, `--expected-migration-name` set to the immutable release Job name, and one reviewed exact workload. The release workflow attests that candidate before atomically assigning release tags, then reads every promoted tag back from the registry and verifies the digest. The laboratory execute overlay sets both `AEGIS_DRY_RUN=false` and `AEGIS_ALLOW_MUTATIONS=true`; merely being able to render it is not approval to apply it.

After the five workloads, secrets, database, migrations, policies, and canary-specific RBAC have been installed through the reviewed release process, inspect the live-runner contract without making changes:

```bash
make live-k3s-acceptance-help
```

`hack/e2e-k3s.py` refuses to proceed unless the current context is exactly `laboratory`, namespace is `outage-arena`, target is `aegissre-e2e-canary`, every AegisSRE workload uses one approved digest and its exact same-named ServiceAccount, both MCP RoleBindings and effective permissions match the bounded graph, the runtime policies/identities/database/network graph match expectations, and an explicit acknowledgement string is supplied. Without `--execute` it performs preflight only. The execute path creates only its marked canary, requires exactly one generation-changing delegated restart, and correlates the resolved outcome and terminal report to the exact target, grant, and incident. The runner never deletes the canary: retain it as evidence, then remove it through reviewed GitOps or a Kubernetes API DELETE preconditioned on the captured object UID. Labels and annotations alone are not deletion authority. This repository has not run that acceptance against the cluster.

Use Flux/GitOps to change workload configuration. Direct `kubectl edit` changes will drift and be reconciled away.

## Pre-live checklist

- [ ] Image is pinned by digest and comes from the expected source.
- [ ] Agent pods have no Kubernetes token.
- [ ] Read and action MCP use distinct ServiceAccounts and Deployments.
- [ ] `kubectl auth can-i --list` for each MCP ServiceAccount matches the reviewed list.
- [ ] Namespace allowlist is exactly `outage-arena`.
- [ ] No wildcard RBAC verbs or resources exist.
- [ ] Default-deny NetworkPolicies and the explicit traffic matrix are enforced.
- [ ] Every application certificate has the correct DNS names, usages, and exactly one expected URI SAN; wrong-role certificates are rejected before body decode.
- [ ] Private signing key exists only in Monitor; overlapping public keyrings exist only in Operator/action MCP, and the rotation sequence has been rehearsed.
- [ ] Exact workload policy, RBAC `resourceNames`, and the grant policy digest agree on one reviewed target/action/signal set.
- [ ] Migration Job completed; runtime roles have no DDL and only their scoped tables; startup and readiness fail on database/schema drift.
- [ ] Expired, altered, wrong-key, wrong-audience, wrong-policy, and wrong-namespace grants are rejected by both verifiers; duplicate delivery returns the durable receipt or an uncertain/replay error without a second blind mutation.
- [ ] Action precondition conflicts fail without mutation.
- [ ] Dry-run produces a receipt and audit record without changing the target.
- [ ] PostgreSQL audit intent/result rows exist for live writes; runtime roles cannot update/delete them; retention and immutable export are operationally owned.
- [ ] A live-success receipt requires an immediate fresh observation; unhealthy/error results remain pending, block redelegation, and receive scheduled read-only follow-ups until recovery or verification-window expiry.
- [ ] Log streams have an authoritative `aegissre.io/workload` identity and traces have authoritative `k8s.namespace.name`/`k8s.deployment.name` resource attributes; missing identity produces no autonomous incident.
- [ ] WhatsApp remains disabled unless the template, scoped token, recipient handling, host-restricted egress proxy, redaction, at-least-once duplicate behavior, retry, and dead-letter handling have been reviewed and tested.
- [ ] OTLP reaches only the expected collector, W3C trace IDs correlate hops, and no authorization/credential material is exported.
- [ ] The gated laboratory acceptance has passed on the approved immutable image; preserve its output and incident/grant IDs as release evidence.
- [ ] Rollback and manual containment have been rehearsed.
- [ ] Security gaps listed in [security-model.md](security-model.md) have an explicit disposition.

## What is not provisioned here

The repository deliberately stops at application code, release scaffolding, and a gated acceptance runner. Before a production claim, another reviewed platform change must provide:

- a published immutable AegisSRE image and deployment-time verification of its provenance/SBOM policy;
- real TLS leaves, overlapping CA trust bundles, delegation keys/keyrings, PostgreSQL URLs/CA, and optional WhatsApp credentials;
- an externally operated highly available PostgreSQL service, role grants, backups, restore tests, monitoring, and retention jobs;
- authoritative collector-side `aegissre.io/workload`, `k8s.namespace.name`, and `k8s.deployment.name` enrichment in the sibling outage-arena configuration where it is currently absent;
- a platform-owned host-restricted WhatsApp egress proxy/gateway if notifications are enabled;
- live validation of CNI NetworkPolicy behavior, Kubernetes API reachability, Victoria query schemas, and the guarded canary workflow.

None of those external resources was created or changed as part of this repository follow-up, and no live `laboratory` deployment or acceptance run is claimed.

## Rollback and containment

The fastest containment is to set `AEGIS_ALLOW_MUTATIONS=false` and reconcile, or scale the action MCP Deployment to zero through the approved GitOps path. Disabling Monitor signing alone is insufficient if unexpired grants remain valid.

For a faulty release:

1. disable mutations/action MCP;
2. preserve logs, audit events, and incident IDs;
3. revert the image digest/configuration through Git;
4. wait for Flux reconciliation;
5. verify all workloads and telemetry manually;
6. rotate delegation keys if authorization behavior may have been compromised.

See [runbook.md](runbook.md) for incident procedures.
