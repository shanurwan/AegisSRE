# Operations runbook

## Purpose

This runbook covers operating and containing AegisSRE itself. It does not replace an application-specific incident runbook. Commands that mutate the cluster must follow the organization's incident authority and GitOps process.

The safe default is detection and diagnosis with no live mutation.

## Operating modes

| Mode | Expected effect |
|---|---|
| Fixture + dry-run | Local evidence; diagnosis-only without keys, or a simulated receipt with disposable keys; no cluster access |
| Kubernetes + observe only | Live detection/diagnosis; no delegation private key or action plane |
| Kubernetes + action dry-run | Full authorization path; Kubernetes dry-run/status only |
| Kubernetes + live action | One allowlisted action after all gates pass |

Confirm the active mode from process configuration, rendered release profile, and structured startup log; do not infer it from a Deployment name alone.

## Startup order

For local processes:

```bash
# Terminal 1: read MCP
go run ./cmd/aegissre mcp-server --profile=read

# Terminal 2: action MCP (keep mutations disabled)
go run ./cmd/aegissre mcp-server --profile=action

# Terminal 3
go run ./cmd/aegissre investigator

# Terminal 4
go run ./cmd/aegissre operator

# Terminal 5: start last
go run ./cmd/aegissre monitor
```

Each process defaults to `:8080`; local simultaneous processes therefore need distinct `AEGIS_LISTEN_ADDR` and matching URL variables, as shown in [.env.example](../.env.example). Compose is the preferred local multi-process runner.

For Kubernetes, run the immutable release migration Job to completion before starting Monitor, Operator, or action MCP, then follow the rollout order in [deployment.md](deployment.md).

## Preflight

Before starting Monitor:

1. Confirm every process has the exact HTTPS public URL, mTLS application listener, and separate unexposed admin listener expected by the render.
2. Confirm `AEGIS_ALLOWED_NAMESPACE=outage-arena`.
3. Confirm `AEGIS_DRY_RUN=true` and `AEGIS_ALLOW_MUTATIONS=false` unless a reviewed live window is active.
4. Confirm read MCP can reach VictoriaMetrics, VictoriaLogs, and VictoriaTraces; validate the required workload identity fields before enabling autonomous log/trace incidents.
5. Confirm the read ServiceAccount can read only expected objects.
6. Confirm action MCP and Operator have the intended public keyring but never a private signing key.
7. Confirm Monitor's `AEGIS_DELEGATION_KEY_ID` exists in both verifier keyrings; during rotation, confirm old/new overlap before changing the signer.
8. Confirm Monitor either has the intended private key or is deliberately diagnosis-only.
9. Confirm system clocks are synchronized.
10. Confirm the exact workload policy, its target/action/signal bounds, and Kubernetes RBAC `resourceNames` agree.
11. Confirm migrations completed, each runtime role can access only its scoped tables, `/readyz` is healthy, and backups/restore monitoring are in place.
12. Confirm durable audit rows are being retained/exported and no execution or outbox row is unexpectedly `uncertain`/`dead_letter`.
13. If WhatsApp is enabled, confirm the approved duplicate-safe template, pinned Graph version, scoped token, recipient, restricted egress proxy, and a non-production destination.

Probe the admin listener's `/healthz` for process health and `/readyz` for readiness. Database consumers continuously ping PostgreSQL and verify embedded migration versions/checksums on readiness; `/readyz` does not prove MCP, A2A, Victoria, Kubernetes, Meta, or model-provider health. Scrape `/metrics` for Go/process/build metrics and perform bounded dependency checks during preflight.

Confirm OTLP/HTTP traces reach only the expected in-cluster collector and that `trace_id`/`span_id` correlate JSON logs across hops. The exporter is enabled only when a standard OTLP endpoint is set; an absent endpoint intentionally uses a no-op provider. Do not treat caller-supplied trace context as authenticated identity.

## Normal incident lifecycle

### 1. Detection

Monitor evaluates server-owned metric, structured-log, and trace templates immediately at startup and then on its configured interval. It has no external trigger: inbound Monitor A2A requests are rejected, and the base NetworkPolicy grants Monitor no ingress. Capture:

- incident ID and first-seen time;
- rule/template ID;
- namespace and workload;
- observed sample values and query time;
- the number of consecutive verification observations.

A single transient sample should not trigger a live change.

The same rule/namespace/Deployment fingerprint must qualify in `AEGIS_VERIFICATION_COUNT` consecutive scans. Each signal rule keeps its own temporal counter; a workload-level cooldown/pending lock prevents simultaneous metric, log, and trace findings from authorizing parallel remediation. Duplicate samples within one response count once. An incident ID is created only when the threshold is reached.

### 2. Investigation

Investigator collects only the evidence budget allowed by configuration. Review the structured diagnosis for:

- evidence references and their timestamps;
- primary and alternative hypotheses;
- confidence and uncertainty;
- proposed typed action and target;
- any missing signal that makes the result indeterminate.

Text found in logs is data, not an instruction. A diagnosis with no supporting evidence must not receive a grant.

The deterministic heuristic reasoner is the default. When all of `AEGIS_LLM_BASE_URL`, `AEGIS_LLM_API_KEY`, and `AEGIS_LLM_MODEL` are configured, the Responses API adapter is primary and falls back to the deterministic reasoner only on an error. A successful inconclusive provider result remains inconclusive. In Kubernetes, an external provider is unreachable under the base NetworkPolicy unless an explicit reviewed egress overlay has been deployed.

### 3. Delegation

Monitor policy either denies the proposal or signs one exact grant. For a production rollout, the durable audit record must include:

- grant and incident IDs;
- diagnosis digest;
- issuer/audience;
- action, target, and preconditions;
- issued/not-before/expiry times;
- dry-run posture;
- signature key ID;
- effective workload-policy digest;
- decision reason.

PostgreSQL audit records are append-only at the application layer. The execution ledger separately retains the exact signed grant and receipt. Treat database role/retention/export gaps as blockers rather than logging a private key or bearer material as a workaround.

Do not extend an expiring grant. Re-observe and issue a new grant if the incident and preconditions still hold.

After diagnosis and before signing, Monitor fetches a fresh workload snapshot. If observed generation and replica availability already meet the health criteria, it returns `resolved_without_action` and emits no grant. Otherwise the grant binds that snapshot's resource version and expected replica count. Investigator's exact proposal defines the task, but only Monitor's signed grant delegates authority.

### 4. Execution

Operator and action MCP must both authorize the grant. Current successful receipts use these domain outcomes:

- `dry_run`: request validated without a persistent mutation;
- `succeeded`: API accepted an authorized live mutation.

Rejected first-use grants and backend/precondition failures return structured errors rather than fabricated success receipts. Use their stable reason codes. In durable mode, Operator and action MCP each reserve the grant in an independent ledger scope before proceeding. Exact duplicates return a completed receipt. `AEGIS_STATE_LEASE` must exceed `AEGIS_REQUEST_TIMEOUT` by more than ten seconds for both durable execution roles. After an expired Operator lease is taken over, `k8s_get_remediation_result` recovers an exact downstream completion without checking grant freshness; `not_found` must pass fresh Operator authorization. If that authorization fails, Operator records `uncertain` because a canceled predecessor may still be accepted after the lookup miss; it never fabricates a no-mutation rejection. For downstream `reserved`, Operator calls only the exact action endpoint: a live action-MCP lease returns retryable replay, while an expired lease is atomically taken over and reconciled against the exact Kubernetes marker/postcondition. Any retry-safe mutation still requires fresh action-MCP authorization. If current authorization or the mutation switch denies that recovered retry, action MCP also records `uncertain`: bounded local request windows cannot prove a previously sent Kubernetes request will not be accepted late. Operator transport errors and receipt-commit acknowledgement failures remain reserved for recovery; a durable downstream `uncertain` state or invalid authenticated receipt becomes uncertain and requires human reconciliation. A changed grant reusing the grant ID or idempotency key is rejected. The domain also reserves `failed`, `rolled_back`, and `escalated` receipt values for adapters/workflows that explicitly produce them.

Scale policy requires `requested replicas > signed expected replicas`; both equality and autonomous scale-down are denied. Unless deliberately changed on Monitor, Operator, and action MCP together, requested replicas are capped at 20 and `requested - expected` is capped at 5.

### 5. Verification

After a `succeeded` live action, Monitor performs an immediate, bounded workload observation and resolves only if it meets availability criteria. If the observation fails or remains unhealthy, the original incident remains in `remediating` with outcome status `verification_pending`. In durable mode, Monitor checkpoints confirmation, dispatch, receipt, pending verification, pending report, and cooldown state under a fenced namespace lease. A replacement replica resumes only after lease takeover. At the start of every scheduled scan it resumes stored workflow work before new detection queries, even when the original signal is absent or a later detection query fails. Pending verification blocks new delegation for that workload. These are read-only observation retries; Monitor never resends the action.

`AEGIS_INCIDENT_COOLDOWN` also sets the pending-verification window. A healthy follow-up resolves the original incident. If the window elapses while the workload is unhealthy or unreadable, Monitor transitions that incident to terminal `escalated`. Clearing pending state after either terminal result starts a fresh fingerprint cooldown. During that cooldown Monitor still evaluates configured metric, log, and trace rules but starts no workflow for that workload. If the signal persists after cooldown, it must satisfy the consecutive-scan threshold again and receives a new incident ID, diagnosis, preconditions, and grant. A `dry_run` receipt is escalated immediately without inferring recovery or entering pending verification. Treat an unresolved operational condition as requiring one of:

- continue observing;
- request a new investigation with fresh evidence;
- escalate to a human;
- execute a separately authorized rollback action, if one exists.

An error before a grant resets consecutive confirmation, so a later attempt also starts from fresh verification. An error after a grant marks the incident failed and applies cooldown because the action result may be uncertain.

### 6. Reporting and notification

For every terminal outcome—including verified recovery, dry-run completion, verification timeout, inconclusive diagnosis, policy/authority denial, rejected or validated failed actions, and action outcomes that could not be verified—Monitor signs and sends a sanitized report request back to Operator. An ambiguous post-delegation outcome is terminal `escalated` with reason `action_outcome_unverified`; it is never asserted to be `failed` without a validated failed or rolled-back receipt. Operator verifies the distinct, short-lived report authorization before creating a sealed report and, when configured, sending the approved WhatsApp template. The report contains stable incident/target/state/reason fields and an optional exact receipt summary; it never includes raw logs, bearer tokens, grant signatures, or model-authored prose.

Check incident, queue, and provider results independently:

- incident `resolved`, `escalated`, or `failed` is the reliability result;
- notification `queued` means the signed report and delivery intent are durable;
- outbox `delivered`, `retry_wait`, or `dead_letter` is only messaging state.

A failed WhatsApp request must not retry remediation or rewrite a recovered incident. Exact report-request dedupe survives restart. Delivery is at-least-once, so a provider acceptance followed by a failed database acknowledgement may produce a duplicate after the lease expires. Investigate the existing outbox row before any manual resend.

Report-request v2 keeps one logical `RequestID`, report ID, and signed `ReportCreatedAt`; only its bounded freshness window, signature, and A2A envelope rotate. A pending durable report is retried indefinitely, one bounded attempt at a time. After local expiry, an `INVALID_SIGNATURE` from a retired report key is renewed with the active signer; it is never renewed early. `EXECUTION_PENDING` likewise retains the exact remediation dispatch; it is not a terminal outcome.

Every grant-bound terminal report fences both `operator` and `mcp_action` scopes atomically. Do not bypass a live-lease `EXECUTION_PENDING` response: allow retry until PostgreSQL time declares the lease expired, after which acceptance records uncertainty and closes missing scopes. Completed execution rows remain until this report coupling marks them reported.

## Common failure procedures

### VictoriaMetrics unavailable or malformed

Symptoms:

- read MCP returns a timeout/non-200 response;
- Monitor cannot verify the candidate signal;
- query response is truncated or cannot be decoded.

Actions:

1. Do not create or advance a new candidate incident from the failed detection query; the polling loop logs the error and tries again at the next interval. An existing pending post-action incident may still advance because Monitor checks its workload snapshot first.
2. Confirm the configured URL is `http://vmsingle.observability.svc.cluster.local:8428` in cluster.
3. Check DNS, NetworkPolicy, Service endpoints, and VictoriaMetrics pod readiness.
4. Use Grafana or a direct read-only query to compare the same bounded metric template.
5. Do not fall back to live action based only on logs.

### VictoriaLogs unavailable

Continue with other evidence only if policy permits an explicitly reduced evidence set. Mark log evidence unavailable. Do not convert arbitrary PromQL or Kubernetes reads into an unreviewed replacement tool.

### VictoriaTraces unavailable or missing workload identity

Continue metrics/log monitoring and mark trace evidence unavailable. Confirm the OTEL pipeline supplies authoritative `k8s.namespace.name` and `k8s.deployment.name` resource attributes. AegisSRE intentionally discards unscoped or ambiguously mapped traces; do not infer a Deployment from an arbitrary service name for autonomous action.

### WhatsApp notification failed

Confirm the incident terminal state first; notification failure does not mean remediation failed. Inspect the durable outbox row by report ID and distinguish `retry_wait` from `dead_letter`. Check Operator logs for the sanitized delivery status, Graph API version/template approval, token scope, recipient format, rate limits, and the restricted egress proxy. Never paste an access token into logs or broaden egress to all HTTPS destinations. Do not reset attempts or manually resend until accounting for the at-least-once acceptance/acknowledgement window.

### Observe MCP unavailable

Monitor and Investigator must stop new evidence-dependent progress. A detection-query error is logged and the next scheduled scan tries again; it creates no new candidate incident. Monitor attempts already-pending post-action verification before that detection query. A failed follow-up remains pending within its window and becomes escalated if still unhealthy or unreadable when the window expires. Restart or roll back the read plane; do not route either agent to the action endpoint.

### A2A peer unavailable

The current Monitor does not automatically retry an A2A request. An Investigator failure occurs before grant issuance, resets consecutive confirmation, and a later verified attempt creates a new incident. An Operator failure occurs after a grant, marks that incident failed, and applies fingerprint cooldown. Preserve the logs and grant ID; do not manually create simultaneous Operators or silently resend the mutation.

### Grant rejected

Use the stable denial reason. Typical causes:

| Reason | Response |
|---|---|
| Expired/not yet valid | Check time synchronization, then re-observe and issue a new grant if justified |
| Bad signature/unknown key | Contain action plane; verify key distribution and investigate tampering |
| Wrong audience | Correct service routing/configuration; never add a broader audience ad hoc |
| Action/target mismatch | Treat as tampering or a programming error; do not modify the grant |
| Policy digest mismatch | Stop rollout and restore one reviewed policy version at Monitor, Operator, read MCP, and action MCP |
| Namespace denied | Keep the allowlist; move the workflow through policy review |
| Replay/in progress | Accept the durable completed receipt or wait for the current lease; never repeat the mutation manually |
| Uncertain | Freeze automation for the target and reconcile Kubernetes state, grant marker, both ledger scopes, and audit events |
| Preconditions changed | Re-investigate current state and issue a new grant only if still appropriate |

### Action result is unknown

If the Kubernetes request may have succeeded but the response was lost, Monitor retains the exact signed grant and A2A envelope before delivery:

1. do not create a replacement incident or grant;
2. allow the current Monitor leader to retry only that exact envelope; Operator's durable ledger returns the stored receipt for an accepted grant and does not repeat the side effect;
3. inspect the target generation/state, execution ledger, and append-only audit trail;
4. once Monitor receives the validated receipt, it checkpoints pending verification before observing recovery;
5. if no receipt can be recovered before the bounded incident window, treat the action outcome as unverified and escalate for manual review.

### Action succeeded but service did not recover

1. Confirm the original incident remains `remediating` with status `verification_pending`; do not create or delegate a replacement incident for the same fingerprint.
2. Capture the action receipt and each scheduled post-action observation.
3. Let Monitor retry only the bounded observation until recovery or the `AEGIS_INCIDENT_COOLDOWN` verification window expires; never replay the action as a verification mechanism.
4. On recovery, confirm that the same incident becomes `resolved`. On expiry without recovery, confirm that it becomes terminal `escalated` and escalate with the diagnosis, evidence, exact change, and verification results.

### Crash loop in an AegisSRE component

Disable mutation first if Operator/action MCP behavior is uncertain. Inspect previous container logs, configuration validation errors, certificate validity/identity, memory limits, PostgreSQL/schema readiness, leases, and downstream health. In live mode, a replacement Monitor acquires a fenced namespace lease and restores detection, exact-dispatch, pending-verification, report-delivery, and cooldown state; Operator and action MCP restore receipts/replay state from independently scoped ledgers. If PostgreSQL or its migration checks are unavailable, readiness and control work fail closed. Fixture mode intentionally retains process-local state and loses it on restart.

### PostgreSQL unavailable or schema mismatch

Symptoms include failed startup, `/readyz` returning 503 on Monitor/Operator/action MCP, lease-renewal failure, or an outbox worker stopping Operator.

1. Disable mutations and stop repeated restarts if they obscure evidence.
2. Check the external database endpoint, TLS chain/hostname, role credential, NetworkPolicy selectors, capacity, replication, and storage health.
3. Query the migration ledger with a read-only administrative role and compare it with the immutable release; never edit a stored checksum.
4. Run only the matching image's `aegissre migrate` under the migration role if a reviewed migration is genuinely pending.
5. After recovery, inspect Monitor workflow state, both execution scopes, `uncertain` rows, and stale outbox leases before re-enabling mutation.

Retention jobs must call the bounded execution cleanup repeatedly until fewer than the requested batch size are removed; its count includes ledger rows and report fences. The database caps any caller-supplied cutoff at `CURRENT_TIMESTAMP`, so future wall-clock input cannot erase a fresh replay fence. Delivered outbox rows may be purged independently because the parent report retains immutable `notification_requested` state.

### mTLS identity or certificate failure

Verify the leaf validity interval, client/server extended usages, Service DNS SAN, sole URI SAN, local `AEGIS_TLS_IDENTITY`, CA bundle, trust-domain/system-namespace settings, and peer role. A certificate valid for another AegisSRE workload must still be rejected. Rotate with overlapping CA trust; never disable verification or switch internal URLs to plaintext as an incident workaround.

## Emergency containment

### Stop all automated writes

Preferred GitOps containment:

1. set `AEGIS_ALLOW_MUTATIONS=false` on action MCP;
2. retain `AEGIS_DRY_RUN=true` across Monitor, Operator, and action MCP;
3. reconcile the change;
4. if needed, scale `aegis-mcp-action` to zero through the approved path;
5. verify the action endpoint is unreachable from Operator;
6. preserve audit and application logs.

Do not rely only on stopping Monitor: already-issued, unexpired grants may still be presented.

### Suspected signing-key compromise

1. Disable/stop action MCP.
2. Stop Monitor grant issuance.
3. Preserve logs, durable audit/execution rows, the active public key fingerprint, and `AEGIS_DELEGATION_KEY_ID`.
4. Generate a new keypair in a trusted environment.
5. Add the new public key ID to both verifier keyrings while retaining the old key; roll both verifiers and verify readiness.
6. Replace Monitor's private key file and active key ID; roll Monitor.
7. Because compromise invalidates normal overlap assumptions, keep mutations disabled until every old-key grant/report request has expired and the exposure has been reviewed, then remove the old public key from both rings.
8. Review every grant/action/audit record in the exposure window and resume in dry-run only.

### Suspected action ServiceAccount compromise

1. Stop action MCP.
2. Revoke its token/ServiceAccount bindings using the platform incident process.
3. Inspect Kubernetes audit events and affected workloads.
4. Review and reduce RBAC before issuing a new identity.
5. Rotate delegation keys if the attacker could also capture valid grants.

## Manual evidence bundle for escalation

Provide:

- incident, A2A task/message, grant, action, correlation, trace, and span IDs;
- timeline in UTC;
- target resource and resource versions/generations;
- bounded metric template and samples;
- bounded log detection/search scope, window, grouped counts, and workload-identity provenance—not an uncontrolled full log dump;
- bounded trace template, window, grouped count, and the availability/provenance state of required Kubernetes resource attributes;
- workload snapshot/events;
- diagnosis and digest;
- policy decisions from both verifiers;
- dry-run/live configuration at the time;
- action receipt;
- post-action verification evidence;
- relevant image digest and config revision.

Redact credentials, authorization headers, delegation private keys, raw Secrets, and unnecessary customer data.

## Return to service

After containment or an AegisSRE failure:

1. identify and correct the fault;
2. run unit and policy tests;
3. run the fixture demo with mutations disabled;
4. validate wrong-signature, expired, wrong-audience, replay, and precondition-conflict cases;
5. validate wrong-role mTLS, unknown/retired key IDs, policy-digest drift, lease takeover, uncertain execution, and outbox retry/dead-letter cases;
6. run migrations and verify database/schema readiness with least-privilege runtime roles;
7. deploy read-only and observe at least one full scan window;
8. add action MCP in dry-run and review durable audit/ledger records;
9. run the gated laboratory acceptance on the approved immutable image;
10. re-enable one exact action only with explicit approval.

Document the decision and any new policy limit before closing the operational incident.
