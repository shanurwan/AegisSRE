# Production release scaffold

This overlay is fail-closed by construction. It renders, but cannot run until a
release integration replaces both sentinels:

- the all-zero AegisSRE image digest;
- `replace-before-live` in both MCP Roles and the mounted workload policy.

It also makes delegation-key references mandatory, mounts the same strict
workload-policy document into every action decision point, keeps mutations
disabled, uses `Recreate` for the first production-shaped rollout while
failover is being validated, and requires mTLS
for every agent and MCP application connection. Kubernetes probes use the
separate, unexposed admin listener on port 9090. Application Services expose
only mTLS on port 8443.

The integration must provision these Secrets out of band; no Secret object or
credential value is rendered by this repository:

- `aegis-monitor-tls`, `aegis-investigator-tls`, `aegis-operator-tls`,
  `aegis-mcp-read-tls`, and `aegis-mcp-action-tls`, each with `tls.crt` and
  `tls.key`;
- `aegis-mtls-ca` with the bounded AegisSRE trust bundle in `ca.crt`;
- `aegis-monitor-signing` with `private-key`;
- `aegis-delegation-keyring` with the rotation-safe v1 keyring in
  `trusted-public-keys.json`;
- `aegis-monitor-postgres`, `aegis-operator-postgres`,
  `aegis-mcp-action-postgres`, and `aegis-postgres-migration`, each with a
  least-privilege PostgreSQL connection string in `url`;
- `aegis-postgres-ca` with the database trust anchor in `ca.crt`.

Each leaf certificate needs its Service DNS names, both client-auth and
server-auth usage, and exactly one URI identity of the form
`spiffe://aegissre.internal/ns/outage-arena/sa/<service-account>`. Rotate the CA
and delegation keys with overlap; never replace trust and signer material in a
single step.

Traces are exported through the in-cluster OpenTelemetry Collector on 4318.
The egress rule intersects the `observability` namespace with the collector's
exact workload labels. WhatsApp remains disabled and has no Internet egress;
an enabling overlay must add separately managed credentials and a restricted
egress proxy or gateway.

Read-only telemetry egress is likewise intersected with the `observability`
namespace and the Helm release labels `victoria-metrics`, `victoria-logs`, and
`victoria-traces`. CoreDNS access requires both the `kube-system` namespace and
`k8s-app=kube-dns`; a chart-label change therefore fails closed and must be
reviewed together with this overlay.

The PostgreSQL URLs must select distinct database roles, point to
`aegis-postgres-rw.aegissre-data.svc.cluster.local:5432`, use
`sslmode=verify-full`, and set
`sslrootcert=/var/run/secrets/aegissre/database/ca.crt`. The overlay permits
database egress only to pods labeled `cnpg.io/cluster=aegis-postgres` in the
`aegissre-data` namespace. It does not deploy or own that database.

Run the rendered migration Job to completion before rolling the runtime
Deployments. Release automation must replace
`aegis-postgres-migrate-replace-before-live` with a unique immutable release
name. Runtime startup checks the embedded migration version and checksum and
fails closed on an absent or stale schema; PostgreSQL-backed readiness repeats
that check. Application pods never mount a persistent volume. The repository
does not deploy the database, create least-privilege roles, configure backups,
or run retention cleanup.

Validate scaffolding with:

```text
python scripts/manifest-policy.py --overlay deploy/kubernetes/overlays/production --expected-target replace-before-live --expected-dry-run true --expected-mutations false --profile scaffold
```

A deployable release must use a non-zero digest and an exact workload target.
Validate that final render with `--profile=release`, `--expected-image` set to
the exact scanned repository digest, and `--expected-migration-name` set to the
immutable release Job name. This prevents a merely well-formed but different
artifact or migration from passing the release gate.

The current namespace remains `outage-arena` so identity claims match the
checked-in ServiceAccounts and the laboratory acceptance boundary. A hardened
multi-tenant production integration should move the five control-plane
workloads to a platform-owned `aegissre-system` namespace, then leave only the
target Roles and cross-namespace RoleBindings in `outage-arena`; that migration
must update certificate identities and policy checks together.

The sibling outage-arena collector may still need authoritative workload
identity enrichment before log- or trace-triggered automation is safe. The
laboratory acceptance runner has not been executed, and no external HA
PostgreSQL, real Secrets, published release digest, or WhatsApp egress proxy is
provisioned by this scaffold.
