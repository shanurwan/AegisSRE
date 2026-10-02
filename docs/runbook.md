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

Confirm the active mode from process configuration and the structured startup log. A dedicated audit startup record is not implemented; do not infer mode from a Deployment name.

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

For Kubernetes, follow the rollout order in [deployment.md](deployment.md).

## Preflight

Before starting Monitor:

1. Confirm every process has a unique, correct public/listen URL.
2. Confirm `AEGIS_ALLOWED_NAMESPACE=outage-arena`.
3. Confirm `AEGIS_DRY_RUN=true` and `AEGIS_ALLOW_MUTATIONS=false` unless a reviewed live window is active.
4. Confirm read MCP can reach VictoriaMetrics, VictoriaLogs, and VictoriaTraces; validate the required workload identity fields before enabling autonomous log/trace incidents.
5. Confirm the read ServiceAccount can read only expected objects.
6. Confirm action MCP has a public key but never a private key.
7. Confirm `AEGIS_DELEGATION_KEY_ID` is identical on Monitor, Operator, and action MCP and identifies the distributed keypair.
8. Confirm Monitor either has the intended private key or is deliberately diagnosis-only.
9. Confirm system clocks are synchronized.
10. Confirm the audit output is being collected and redacted.
11. Confirm there is no unresolved prior condition whose pending-verification, cooldown, receipt, report-deduplication, or replay state was lost on restart.
12. If WhatsApp is enabled, confirm the approved template, pinned Graph version, scoped token, recipient, and restricted egress path with a non-production destination.

Probe `/healthz` for process health and `/readyz` for completion of process initialization. Both endpoints are implemented, but `/readyz` is currently shallow and does not continuously check MCP, A2A, Victoria, Kubernetes, or model-provider dependencies. Scrape `/metrics` for Go/process/build metrics and perform direct bounded dependency checks during preflight.

OTLP export is not wired in the current binary, and the base manifests intentionally contain no OTEL environment variables or collector egress. Collect JSON process logs and scrape `/metrics` until an exporter is implemented; do not add collector access on configuration alone.

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
- decision reason.

The current logger-only audit events contain incident, actor, operation, decision, side-effect, and time fields, not this complete grant inventory. Treat that gap as a blocker for live production operation rather than logging the private key or full bearer material as a workaround.

Do not extend an expiring grant. Re-observe and issue a new grant if the incident and preconditions still hold.

After diagnosis and before signing, Monitor fetches a fresh workload snapshot. If observed generation and replica availability already meet the health criteria, it returns `resolved_without_action` and emits no grant. Otherwise the grant binds that snapshot's resource version and expected replica count. Investigator's exact proposal defines the task, but only Monitor's signed grant delegates authority.

### 4. Execution

Operator and action MCP must both authorize the grant. Current successful receipts use these domain outcomes:

- `dry_run`: request validated without a persistent mutation;
- `succeeded`: API accepted an authorized live mutation.

Rejected grants and backend/precondition failures return structured errors rather than fabricated success receipts. Use their stable reason codes. On duplicate delivery, Operator and action MCP return a process-local cached receipt when available. If a live grant was consumed without an Operator receipt, Operator queries `k8s_get_remediation_status` and reports success only when the exact grant-marked postcondition is satisfied; dry-run replay and unsatisfied live status are denied. The domain also reserves `rejected`, `failed`, `rolled_back`, and `escalated` receipt values for adapters/workflows that explicitly produce them.

Scale policy requires `requested replicas > signed expected replicas`; both equality and autonomous scale-down are denied. Unless deliberately changed on Monitor, Operator, and action MCP together, requested replicas are capped at 20 and `requested - expected` is capped at 5.

### 5. Verification

After a `succeeded` live action, Monitor performs an immediate, bounded workload observation and resolves only if it meets availability criteria. If the observation fails or remains unhealthy, the original incident remains in `remediating` with outcome status `verification_pending`. Monitor stores that context in process memory and, at the start of every scheduled scan, retries the exact target observation before running new detection queries. It does so even when the original fingerprint is absent from the configured metric, log, or trace rules or a later detection query fails. Pending verification blocks a new investigation or delegation for that fingerprint. These are read-only observation retries; Monitor never resends the action.

`AEGIS_INCIDENT_COOLDOWN` also sets the pending-verification window. A healthy follow-up resolves the original incident. If the window elapses while the workload is unhealthy or unreadable, Monitor transitions that incident to terminal `escalated`. Clearing pending state after either terminal result starts a fresh fingerprint cooldown. During that cooldown Monitor still evaluates configured metric, log, and trace rules but starts no workflow for that workload. If the signal persists after cooldown, it must satisfy the consecutive-scan threshold again and receives a new incident ID, diagnosis, preconditions, and grant. A `dry_run` receipt is escalated immediately without inferring recovery or entering pending verification. Treat an unresolved operational condition as requiring one of:

- continue observing;
- request a new investigation with fresh evidence;
- escalate to a human;
- execute a separately authorized rollback action, if one exists.

An error before a grant resets consecutive confirmation, so a later attempt also starts from fresh verification. An error after a grant marks the incident failed and applies cooldown because the action result may be uncertain.

### 6. Reporting and notification

For every terminal outcome—including verified recovery, dry-run completion, verification timeout, inconclusive diagnosis, policy/authority denial, rejected or validated failed actions, and action outcomes that could not be verified—Monitor signs and sends a sanitized report request back to Operator. An ambiguous post-delegation outcome is terminal `escalated` with reason `action_outcome_unverified`; it is never asserted to be `failed` without a validated failed or rolled-back receipt. Operator verifies the distinct, short-lived report authorization before creating a sealed report and, when configured, sending the approved WhatsApp template. The report contains stable incident/target/state/reason fields and an optional exact receipt summary; it never includes raw logs, bearer tokens, grant signatures, or model-authored prose.

Check both results independently:

- incident `resolved`, `escalated`, or `failed` is the reliability result;
- notification `delivered` or `failed` is only the messaging result.

A failed WhatsApp request must not retry remediation or rewrite a recovered incident. Operator deduplicates identical request IDs in a bounded process-local cache; after eviction or restart, check the incident timeline before manually resending a report.

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

Confirm the incident terminal state first; notification failure does not mean remediation failed. Check Operator logs for the sanitized delivery status, Graph API version/template approval, token scope, recipient format, rate limits, and the restricted egress proxy. Never paste an access token into logs or broaden egress to all HTTPS destinations. Use the incident report ID as the idempotency reference and avoid duplicate manual sends after an Operator restart.

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
| Namespace denied | Keep the allowlist; move the workflow through policy review |
| Replay | Accept a cached receipt; otherwise allow Operator's live status recovery only when the exact postcondition is satisfied; never repeat the mutation |
| Preconditions changed | Re-investigate current state and issue a new grant only if still appropriate |

### Action result is unknown

If the Kubernetes request may have succeeded but the response was lost, remember that Monitor does not automatically resend it or create pending verification without a validated `succeeded` receipt:

1. do not replay the action immediately;
2. if an authorized duplicate delivery reaches Operator while the grant remains valid, let Operator use its bounded status-recovery path; otherwise inspect cluster state manually under normal runbook authority;
3. inspect current target generation/state and the audit trail;
4. use the status result to determine current state; the current implementation has no durable receipt store;
5. escalate if state cannot be determined safely.

### Action succeeded but service did not recover

1. Confirm the original incident remains `remediating` with status `verification_pending`; do not create or delegate a replacement incident for the same fingerprint.
2. Capture the action receipt and each scheduled post-action observation.
3. Let Monitor retry only the bounded observation until recovery or the `AEGIS_INCIDENT_COOLDOWN` verification window expires; never replay the action as a verification mechanism.
4. On recovery, confirm that the same incident becomes `resolved`. On expiry without recovery, confirm that it becomes terminal `escalated` and escalate with the diagnosis, evidence, exact change, and verification results.

### Crash loop in an AegisSRE component

Disable mutation first if Operator/action MCP behavior is uncertain. Inspect previous container logs, configuration validation errors, memory limits, and dependency readiness. Restarting Monitor loses process-local detection, pending-verification, and cooldown state; restarting a verifier may lose process-local receipts and replay state. Treat either loss as unsafe for live mode until durable stores exist.

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
3. Preserve logs, the active public key fingerprint, and `AEGIS_DELEGATION_KEY_ID`.
4. Generate a new keypair in a trusted environment.
5. Replace the public key and key ID in both verifiers, then the private key and matching key ID in Monitor.
6. Invalidate/reject all grants from the old key.
7. Review every grant/action/audit record in the exposure window.
8. Resume in dry-run only.

### Suspected action ServiceAccount compromise

1. Stop action MCP.
2. Revoke its token/ServiceAccount bindings using the platform incident process.
3. Inspect Kubernetes audit events and affected workloads.
4. Review and reduce RBAC before issuing a new identity.
5. Rotate delegation keys if the attacker could also capture valid grants.

## Manual evidence bundle for escalation

Provide:

- incident, A2A task/message, grant, action, and correlation IDs; include trace IDs only after tracing is implemented;
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
5. deploy read-only and observe at least one full scan window;
6. add action MCP in dry-run;
7. review audit records;
8. re-enable one action only with explicit approval.

Document the decision and any new policy limit before closing the operational incident.
