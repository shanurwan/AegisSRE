# Security pipeline

Every change runs the gates below in [`.github/workflows/security.yml`](../.github/workflows/security.yml), alongside the existing [`test.yml`](../.github/workflows/test.yml) and release-time [`image.yml`](../.github/workflows/image.yml) checks. Each gate is blocking: a finding fails the run. The workflow also runs weekly, so a newly published CVE fails `main` without a code change.

| Gate | Tool | What fails the build |
|---|---|---|
| Secrets | gitleaks 8.30.1, checksum-pinned | Any secret in any commit of the full history |
| SAST | gosec 2.30.0 | Any finding. Suppressions are inline `#nosec <rule> -- reason` and reviewed. |
| SAST | Semgrep 1.183.0 (`p/golang`, `p/dockerfile`, `p/github-actions`) | Any finding |
| SAST | CodeQL `security-extended` | Any result. Runs once the repository is public (see below). |
| Dependencies | govulncheck (in `test.yml`) | A known vulnerability on a reachable call path |
| Dependencies | OSV-Scanner 2.7.0, Trivy `fs` | Any known-vulnerable module, reachable or not; any HIGH/CRITICAL; any committed secret |
| Container | Trivy on the built image (in `test.yml` and `image.yml`) | Any fixable HIGH/CRITICAL in the OS or Go binary, per platform digest, before release tags exist |
| IaC | Trivy `config` | Any HIGH/CRITICAL misconfiguration in every rendered Kubernetes variant, the Dockerfiles or Compose |
| CI/CD | actionlint 1.7.12 (with shellcheck), zizmor 1.31.1 | Workflow errors, script bugs, credential persistence, cache poisoning, template injection, unpinned actions |
| DAST | OWASP ZAP API scan, active | Any Low-or-higher alert on any of the five services that is not an exact reviewed exception |
| IAST | Race- and coverage-instrumented build under the same ZAP traffic | A data race, a panic, a crash-restart, a non-zero exit, or attack traffic never reaching the security-boundary packages |

Dependabot keeps Go modules, SHA-pinned Actions and digest-pinned base images current. Each update still has to pass these gates.

## DAST

[`security/dast/scan.sh`](../security/dast/scan.sh) starts the release image in the Compose fixture topology and attacks all five services in parallel, one fresh ZAP container each. ZAP joins the same segmented `observe`, `control` and `operate` networks as the services. The attack surface is described in [`agents.openapi.yaml`](../security/dast/agents.openapi.yaml) and [`mcp.openapi.yaml`](../security/dast/mcp.openapi.yaml), so ZAP sends real A2A JSON-RPC and MCP `tools/call` shapes instead of crawling blind.

[`gate.py`](../security/dast/gate.py) fails on any alert of Low risk or above unless it matches one entry in [`accepted-risks.json`](../security/dast/accepted-risks.json). Each entry names one rule, one method and one path, and records why the risk is accepted. Accepting a rule on one path never hides that rule anywhere else.

There is one accepted risk. The A2A Agent Card is a public discovery document, so it is served with `Access-Control-Allow-Origin: *` and never with credentials.

## IAST

There is no open-source IAST agent for Go. Commercial agents mostly cover the JVM, .NET and Node. AegisSRE therefore instruments itself with the Go toolchain: [`security/iast/Dockerfile`](../security/iast/Dockerfile) builds the same sources with `-race` and `-cover`. The topology runs with the same hardened Compose settings, and [`assess.sh`](../security/iast/assess.sh) judges the run after the DAST traffic. It fails on any of these:

- a race detector report;
- a panic or fatal error in any process log;
- a container that restarted or exited non-zero;
- missing coverage, meaning a process did not shut down cleanly;
- 0% coverage in `internal/security`, `internal/transport/a2a` or `internal/transport/mcp`, which would mean the attack never reached the code that enforces the boundary.

The coverage profile is kept as an artifact, so you can see exactly which code the attack exercised.

## Findings fixed while building this

- The Go 1.26.8 toolchain had four HIGH stdlib CVEs, including a crypto/x509 man-in-the-middle bug (CVE-2026-111943), which matters to an mTLS-based design. Moved to 1.26.10.
- `golang.org/x/mod` CVE-2026-56864/56865 (sumdb integrity) and `golang.org/x/net` CVE-2026-78669 (HTTP/2 DoS) were upgraded. The x/mod one had been failing CI on `main`.
- The A2A SDK reflected any `Origin` together with `Access-Control-Allow-Credentials: true` on the Agent Card. That card is now a credential-free public document (`publicDocument`, regression-tested).
- Every listener now sends `X-Content-Type-Options: nosniff` and `Cross-Origin-Resource-Policy: same-origin`.
- Workflow checkouts no longer persist the job token, and the release job no longer restores a shared Go build cache.

## Limits

These gates are strong automated evidence. They are not a penetration test or a certification.

- DAST and IAST exercise the local fixture topology, which runs plaintext without delegation keys. The mTLS caller matrix (`transport/authn`, `platform/tlsconfig`) and signed-grant execution through Operator are covered by unit and E2E tests, not by the dynamic scans.
- The private repository has no GitHub Advanced Security, so CodeQL is skipped and reports are kept as artifacts instead of code-scanning alerts. Making the repository public enables both at no cost.
- A manual assessment should still target the delegation protocol, the MCP routing-header and body agreement, and the production NetworkPolicies. [SECURITY.md](../SECURITY.md) lists the high-priority classes.

## Running the gates locally

All of these need Docker. Reports go to `build/`, which git ignores.

```bash
make security-dast   # release image + ZAP against all five services
make security-iast   # instrumented image + ZAP + race/crash/reach assessment
```

Static gates use the same pinned versions as CI, for example:

```bash
go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 ./...
go run github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0 scan source --recursive .
```
