# Security policy

## Supported versions

AegisSRE is currently pre-release software. No production-supported release line exists yet.

| Version | Security fixes |
|---|---|
| Current `main` | Best effort |
| Older commits or forks | Not maintained by this project |

Security fixes may change protocol, configuration, persistence, or policy behavior while the project remains pre-1.0. Pinning a commit transfers responsibility for backporting later fixes to the deployer.

## Report a vulnerability

Please do not disclose a vulnerability in a public issue, discussion, pull request, log excerpt, or demo.

Use GitHub's private vulnerability reporting for this repository from the **Security** tab when it is available. Include:

- a concise description and affected commit/version;
- the component and deployment mode involved;
- reproduction steps or a minimal proof of concept;
- the security boundary that is bypassed;
- realistic impact and required attacker access;
- any suggested mitigation;
- whether keys, credentials, or live infrastructure may already be exposed.

If private vulnerability reporting is unavailable, open a public issue containing only a request for a private security contact. Do not include exploit details or secrets.

The maintainers will assess reports as project capacity allows. This pre-release project does not currently promise a response or remediation SLA. Coordinated disclosure timing will be agreed case by case.

## High-priority findings

Reports are especially valuable when they demonstrate:

- delegation signature, canonicalization, expiry, audience, incident, or parameter-binding bypass;
- replay or duplicate execution of an action;
- a path from Investigator/Monitor to Kubernetes write authority without a valid grant;
- observe-plane access to write tools or action-plane access beyond its Role;
- namespace allowlist escape;
- arbitrary PromQL, LogsQL, Kubernetes patch, manifest, shell, pod exec, or secret access;
- dry-run or `AEGIS_ALLOW_MUTATIONS` bypass;
- A2A/MCP authentication or authorization confusion;
- request smuggling or disagreement between MCP routing headers and the JSON-RPC body;
- credential/private-key disclosure in logs, traces, metrics, errors, images, or artifacts;
- unsafe deserialization, unbounded resource consumption, or SSRF through a tool input;
- a supply-chain issue affecting the published image or build workflow.

## Out of scope

Unless a project defect makes them possible, the following are normally out of scope:

- attacks requiring prior administrator access to the Kubernetes node/control plane;
- intentionally broad RBAC or disabled NetworkPolicies in a downstream deployment;
- social engineering, denial-of-service traffic against an intentionally unauthenticated local fixture, or exposed demo keys;
- vulnerabilities only in unsupported dependencies with no demonstrated AegisSRE impact;
- findings based only on the documentation's target architecture when the feature is clearly marked unimplemented.

Do not test against infrastructure you do not own or have explicit permission to assess. Do not perform a live remediation to prove impact.

## Handling sensitive material

Never attach:

- `AEGIS_DELEGATION_PRIVATE_KEY`;
- model-provider API keys;
- Kubernetes tokens or kubeconfigs;
- raw Secrets;
- authorization headers;
- Terraform state or outage-arena credentials;
- unredacted customer/application logs.

Use synthetic identifiers and fixture data. If a secret was exposed, revoke/rotate it before reporting when that can be done safely.

## Deployment responsibility

The checked-in manifests are a security-oriented starting point, not a certification. Deployers must validate image pinning, RBAC, NetworkPolicies, workload identity/TLS, secret distribution, audit retention, replay storage, admission policy, and workload-specific remediation behavior in their own environment.

See [the security model](docs/security-model.md) and [operations runbook](docs/runbook.md).
