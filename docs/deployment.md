# Deployment

## Status and scope

This guide covers the checked-in Kustomize deployment for the `laboratory` k3s cluster and its `outage-arena` namespace. The manifests provide a security-oriented starting point with separate workloads, ServiceAccounts, Roles, Services, and NetworkPolicies. Their presence is not evidence that an image has been published, the manifests have been applied, or all live adapters and controls have been verified.

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
| `aegis-operator` | `aegissre operator` | none | Action MCP |
| `aegis-mcp-read` | `aegissre mcp-server --profile=read` | read-only ServiceAccount | Kubernetes API, VictoriaMetrics, VictoriaLogs |
| `aegis-mcp-action` | `aegissre mcp-server --profile=action` | minimal write ServiceAccount | Kubernetes API |

Each workload listens on `:8080` by default. Give every workload a ClusterIP Service; do not expose agent or MCP endpoints through the public Gateway for the first deployment.

The current binary does not initialize an OTLP exporter, and the base manifests intentionally provide neither OTEL environment variables nor collector egress. `/metrics` exposes the implemented Prometheus process/build metrics. Add OTLP configuration and narrowly scoped network access only together with an implemented, tested exporter.

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
| `AEGIS_LISTEN_ADDR` | `:8080` | all |
| `AEGIS_PUBLIC_URL` | workload Service URL | all A2A-serving agents |
| `AEGIS_ALLOWED_NAMESPACE` | `outage-arena` | all; enforce again in both MCP planes |
| `AEGIS_OBSERVE_MCP_URL` | `http://aegis-mcp-read:8080/mcp` | Monitor, Investigator |
| `AEGIS_OPERATE_MCP_URL` | `http://aegis-mcp-action:8080/mcp` | Operator |
| `AEGIS_INVESTIGATOR_URL` | `http://aegis-investigator:8080` | Monitor |
| `AEGIS_OPERATOR_URL` | `http://aegis-operator:8080` | Monitor |
| `AEGIS_VICTORIA_METRICS_URL` | `http://vmsingle.observability.svc.cluster.local:8428` | read MCP |
| `AEGIS_VICTORIA_LOGS_URL` | `http://vlogs.observability.svc.cluster.local:9428` | read MCP |
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
The checked-in base explicitly pins both scale limits to the defaults. Keep the same values on Monitor, Operator, and action MCP so policy cannot disagree across verification boundaries.

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

- `AEGIS_DELEGATION_PRIVATE_KEY`: Monitor only.
- `AEGIS_DELEGATION_PUBLIC_KEY`: Operator and action MCP.
- `AEGIS_DELEGATION_KEY_ID`: the same non-secret identifier on all three; `keygen` emits the default `aegissre-monitor-v1`.
- read MCP and Investigator receive neither key.

Create the Kubernetes Secret out of band or through the cluster's approved secret manager. Do not put key values in this repository, a Kustomization, a shell history, a ticket, or a screenshot.

When no private key is configured, Monitor remains capable of detection and diagnosis but does not delegate an action.

## Kubernetes RBAC

### Read plane

Create a dedicated ServiceAccount for `aegis-mcp-read`. The current Kubernetes adapter's implemented calls require this namespaced surface:

```text
pods:                    list
pods/log:                get
deployments:             get
events (core API):       list
```

The checked-in read Role matches those exact calls, including `get` on the `pods/log` subresource separately from Pod object verbs. Validate pod-log access with `kubectl auth can-i get pods/log --as=system:serviceaccount:outage-arena:aegis-mcp-read -n outage-arena`; treat a denial as deployment drift or binding failure, not a reason to grant a broader role.

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
| Monitor | Operator | A2A delegated action task |
| Investigator | read MCP | evidence collection |
| Operator | action MCP | exact remediation call/status |
| read MCP | Kubernetes API | bounded object reads/pod logs |
| read MCP | VictoriaMetrics/VictoriaLogs | bounded signal queries |
| action MCP | Kubernetes API | allowlisted mutations/status |
| Investigator | approved model endpoint | not allowed by base; only through an explicit reviewed overlay |

The checked-in policies permit DNS and the internal rows above. They grant no collector egress and deliberately block external model egress. Deny direct Operator-to-Kubernetes and Investigator-to-action-MCP traffic even if application policy would reject it.

There is intentionally no ingress rule for Monitor. It self-polls on `AEGIS_SCAN_INTERVAL`, and its current A2A handler rejects inbound workflow requests. Do not add an alert bridge or webhook ingress until an authenticated, authorized, replay-safe trigger is implemented and reviewed.

## Resource and availability guidance

Begin with one replica per component while detection, pending-verification, and cooldown tracking, receipt caches, and replay guards are process-local. Horizontal replicas are unsafe if they can independently accept the same grant without shared replay state.

Set:

- a non-root user, read-only root filesystem, dropped Linux capabilities, and seccomp `RuntimeDefault`;
- CPU/memory requests and limits after fixture/load measurements;
- startup/readiness/liveness probes on the implemented `/healthz` and `/readyz` endpoints, recognizing that `/readyz` is currently a shallow process-ready check rather than continuous dependency health;
- graceful termination long enough to finish or cancel an in-flight bounded request;
- PodDisruptionBudgets only after multi-replica state semantics exist.

Avoid making the safety-critical action plane highly available before its idempotency and replay storage are highly available.

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

Render the safe overlay before integrating it into Flux:

```bash
kubectl kustomize deploy/kubernetes/overlays/dry-run
```

The `execute` overlay sets both `AEGIS_DRY_RUN=false` and `AEGIS_ALLOW_MUTATIONS=true`. Merely being able to render it is not approval to apply it. The base currently references an image tag; patch it to an immutable digest in the deployment integration before rollout.

Use Flux/GitOps to change workload configuration. Direct `kubectl edit` changes will drift and be reconciled away.

## Pre-live checklist

- [ ] Image is pinned by digest and comes from the expected source.
- [ ] Agent pods have no Kubernetes token.
- [ ] Read and action MCP use distinct ServiceAccounts and Deployments.
- [ ] `kubectl auth can-i --list` for each MCP ServiceAccount matches the reviewed list.
- [ ] Namespace allowlist is exactly `outage-arena`.
- [ ] No wildcard RBAC verbs or resources exist.
- [ ] Default-deny NetworkPolicies and the explicit traffic matrix are enforced.
- [ ] Private signing key exists only in Monitor; public key exists only where needed.
- [ ] Expired, altered, wrong-audience, and wrong-namespace grants are rejected by both verifiers; duplicate delivery never causes a second mutation and exercises the reviewed cache, bounded status-recovery, or replay-denial path.
- [ ] Action precondition conflicts fail without mutation.
- [ ] Dry-run produces a receipt and audit record without changing the target.
- [ ] A durable audit sink has replaced the current logger-only adapter, and its failure fails closed for live writes.
- [ ] A live-success receipt requires an immediate fresh observation; unhealthy/error results remain pending, block redelegation, and receive scheduled read-only follow-ups until recovery or verification-window expiry.
- [ ] Rollback and manual containment have been rehearsed.
- [ ] Security gaps listed in [security-model.md](security-model.md) have an explicit disposition.

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
