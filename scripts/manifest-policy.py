#!/usr/bin/env python3
"""Validate safety invariants in a rendered AegisSRE Kustomize overlay.

The checker intentionally uses only the Python standard library and kubectl so
it is runnable in the existing CI image and on the Windows operator workstation.
It parses only deterministic fields in manifests produced by this repository;
it is not a general-purpose YAML parser.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass


ZERO_DIGEST = "sha256:" + "0" * 64
IMAGE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
EXPECTED_DEPLOYMENTS = {
    "aegis-monitor",
    "aegis-investigator",
    "aegis-operator",
    "aegis-mcp-read",
    "aegis-mcp-action",
}
EXPECTED_SERVICES = EXPECTED_DEPLOYMENTS
EXPECTED_SERVICE_ACCOUNTS = EXPECTED_DEPLOYMENTS
EXPECTED_ROLES = {"aegis-mcp-read", "aegis-mcp-action"}
EXPECTED_ROLE_BINDINGS = EXPECTED_ROLES
EXPECTED_NETWORK_POLICIES = {
    "aegis-default-deny",
    "aegis-dns-egress",
    "aegis-investigator-egress",
    "aegis-investigator-ingress",
    "aegis-mcp-action-ingress",
    "aegis-mcp-kubernetes-api-egress",
    "aegis-mcp-read-ingress",
    "aegis-mcp-read-telemetry-egress",
    "aegis-monitor-egress",
    "aegis-operator-egress",
    "aegis-operator-ingress",
    "aegis-otlp-egress",
    "aegis-postgres-egress",
}
EXPECTED_KINDS = {
    "ConfigMap", "Deployment", "Job", "NetworkPolicy", "Role",
    "RoleBinding", "Service", "ServiceAccount",
}
EXPECTED_IDENTITIES = {
    name: f"spiffe://aegissre.internal/ns/outage-arena/sa/{name}"
    for name in EXPECTED_DEPLOYMENTS
}
EXPECTED_PUBLIC_URLS = {
    name: f"https://{name}:8443"
    for name in EXPECTED_DEPLOYMENTS
}


@dataclass(frozen=True)
class Document:
    kind: str
    name: str
    text: str


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def scalar_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def top_level_scalar(text: str, key: str) -> str:
    prefix = key + ":"
    for line in text.splitlines():
        if indentation(line) == 0 and line.startswith(prefix):
            return scalar_value(line[len(prefix) :])
    return ""


def metadata_name(text: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line == "metadata:":
            for candidate in lines[index + 1 :]:
                if candidate and indentation(candidate) == 0:
                    break
                if indentation(candidate) == 2 and candidate.strip().startswith("name:"):
                    return scalar_value(candidate.strip().split(":", 1)[1])
    return ""


def split_documents(rendered: str) -> list[Document]:
    result: list[Document] = []
    for raw in re.split(r"(?m)^---\s*$", rendered):
        text = raw.strip()
        if not text:
            continue
        kind = top_level_scalar(text, "kind")
        name = metadata_name(text)
        if kind and name:
            result.append(Document(kind=kind, name=name, text=text))
    return result


def mapping(text: str, key: str) -> dict[str, str]:
    lines = text.splitlines()
    result: dict[str, str] = {}
    for index, line in enumerate(lines):
        if line.strip() != key + ":":
            continue
        base = indentation(line)
        for candidate in lines[index + 1 :]:
            stripped = candidate.strip()
            if stripped and indentation(candidate) <= base:
                break
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            child_key, value = stripped.split(":", 1)
            if indentation(candidate) == base + 2:
                result[scalar_value(child_key)] = scalar_value(value)
        if result:
            return result
    return result


def all_list_values(text: str, key: str) -> list[str]:
    lines = text.splitlines()
    values: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() != key + ":":
            continue
        base = indentation(line)
        for candidate in lines[index + 1 :]:
            stripped = candidate.strip()
            candidate_indent = indentation(candidate)
            if stripped.startswith("- ") and candidate_indent >= base:
                values.append(scalar_value(stripped[2:]))
                continue
            if stripped and candidate_indent <= base:
                break
    return values


def normalized_role_rules(text: str) -> set[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]]:
    """Parse the deterministic kubectl-kustomize Role rule shape."""
    rules: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] | None = None
    active_key = ""
    in_rules = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "rules:":
            in_rules = True
            continue
        if not in_rules:
            continue
        if line == "- apiGroups:":
            current = {"apiGroups": [], "resources": [], "verbs": [], "resourceNames": []}
            rules.append(current)
            active_key = "apiGroups"
            continue
        if current is None:
            continue
        if indentation(line) == 2 and stripped.endswith(":") and not stripped.startswith("- "):
            active_key = stripped[:-1]
            continue
        if indentation(line) == 2 and stripped.startswith("- ") and active_key in current:
            current[active_key].append(scalar_value(stripped[2:]))
    return {
        (
            tuple(sorted(rule["apiGroups"])),
            tuple(sorted(rule["resources"])),
            tuple(sorted(rule["verbs"])),
            tuple(sorted(rule["resourceNames"])),
        )
        for rule in rules
    }


def values_for_key(text: str, key: str) -> list[str]:
    pattern = re.compile(r"(?m)^\s*" + re.escape(key) + r":\s*([^#\r\n]+)")
    return [scalar_value(match.group(1)) for match in pattern.finditer(text)]


def env_block(text: str, variable: str) -> str:
    lines = text.splitlines()
    needle = "- name: " + variable
    for index, line in enumerate(lines):
        if line.strip() != needle:
            continue
        base = indentation(line)
        block = [line]
        for candidate in lines[index + 1 :]:
            stripped = candidate.strip()
            if stripped.startswith("- name:") and indentation(candidate) == base:
                break
            if stripped and indentation(candidate) < base:
                break
            block.append(candidate)
        return "\n".join(block)
    return ""


def literal_block(text: str, key: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.fullmatch(r"\s*" + re.escape(key) + r":\s*[|>]-?\s*", line):
            continue
        base = indentation(line)
        content: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() and indentation(candidate) <= base:
                break
            trim = min(len(candidate), base + 2)
            content.append(candidate[trim:])
        return "\n".join(content).rstrip() + "\n"
    return ""


def rendered_overlay(path: pathlib.Path) -> str:
    completed = subprocess.run(
        ["kubectl", "kustomize", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "kubectl kustomize failed")
    return completed.stdout


def parse_bool(value: str) -> bool:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def image_reference(value: str) -> str:
    if not IMAGE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("expected an image reference pinned by sha256 digest")
    return value


def validate(args: argparse.Namespace, documents: list[Document]) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    deployments = {doc.name: doc for doc in documents if doc.kind == "Deployment"}
    jobs = {doc.name: doc for doc in documents if doc.kind == "Job"}
    services = {doc.name: doc for doc in documents if doc.kind == "Service"}
    service_accounts = {doc.name: doc for doc in documents if doc.kind == "ServiceAccount"}
    roles = {doc.name: doc for doc in documents if doc.kind == "Role"}
    role_bindings = {doc.name: doc for doc in documents if doc.kind == "RoleBinding"}
    config_maps = [doc for doc in documents if doc.kind == "ConfigMap"]
    network_policies = {doc.name: doc for doc in documents if doc.kind == "NetworkPolicy"}

    require(all(doc.kind in EXPECTED_KINDS for doc in documents),
            "render contains a resource kind outside the exact release inventory")
    require(set(deployments) == EXPECTED_DEPLOYMENTS, "render must contain exactly the five AegisSRE Deployments")
    require(len(jobs) == 1, "render must contain exactly one PostgreSQL migration Job")
    require(set(services) == EXPECTED_SERVICES, "render must contain exactly the five internal AegisSRE Services")
    require(set(service_accounts) == EXPECTED_SERVICE_ACCOUNTS,
            "render must contain exactly the five AegisSRE ServiceAccounts")
    require(set(roles) == EXPECTED_ROLES, "render must contain exactly the two constrained MCP Roles")
    require(set(role_bindings) == EXPECTED_ROLE_BINDINGS,
            "render must contain exactly the two constrained MCP RoleBindings")
    require(set(network_policies) == EXPECTED_NETWORK_POLICIES,
            "render NetworkPolicy inventory differs from the exact reviewed graph")
    require(len(config_maps) == 2 and
            sum(doc.name.startswith("aegis-config-") for doc in config_maps) == 1 and
            sum(doc.name.startswith("aegis-workload-policy-") for doc in config_maps) == 1,
            "render must contain exactly the generated runtime config and workload policy ConfigMaps")
    require(not any(doc.kind in {"Ingress", "Gateway", "HTTPRoute", "GRPCRoute"} for doc in documents),
            "agent and MCP endpoints must not be publicly routed")
    require(not any(doc.kind == "Secret" for doc in documents), "render must not contain committed Secret material")

    for name, binding in sorted(role_bindings.items()):
        require(binding.text.count("apiGroup: rbac.authorization.k8s.io") == 1 and
                len(re.findall(r"(?m)^\s*kind:\s*Role\s*$", binding.text)) == 1 and
                binding.text.count(f"name: {name}") == 3 and
                len(re.findall(r"(?m)^\s*-?\s*kind:\s*ServiceAccount\s*$", binding.text)) == 1 and
                binding.text.count("namespace: outage-arena") == 2,
                f"{name} RoleBinding must bind only its same-named ServiceAccount to its same-named Role")

    for name, deployment in sorted(deployments.items()):
        images = [scalar_value(value) for value in re.findall(r"(?m)^\s*image:\s*([^#\r\n]+)", deployment.text)]
        require(len(images) == 1, f"{name} must contain exactly one container image")
        for image in images:
            require(bool(IMAGE_PATTERN.fullmatch(image)), f"{name} image must be pinned by sha256 digest")
            if args.expected_image:
                require(image == args.expected_image,
                        f"{name} image differs from the expected release artifact")
            if args.profile == "release":
                require(not image.endswith("@" + ZERO_DIGEST), f"{name} still uses the non-pullable zero digest")
        require("type: Recreate" in deployment.text, f"{name} must use Recreate while workflow state is singleton")
        require("enableServiceLinks: false" in deployment.text, f"{name} must disable Kubernetes service-link injection")
        require("imagePullPolicy: IfNotPresent" in deployment.text, f"{name} must use digest-compatible IfNotPresent pulls")

        automount = values_for_key(deployment.text, "automountServiceAccountToken")
        expected_mount = "true" if name in {"aegis-mcp-read", "aegis-mcp-action"} else "false"
        require(expected_mount in automount, f"{name} has the wrong ServiceAccount-token mount policy")

        assurance = values_for_key(deployment.text, "aegissre.io/transport-assurance")
        require(assurance == ["authenticated-encrypted"],
                f"{name} must declare authenticated encrypted transport")
        require("containerPort: 8443" in deployment.text and "name: https" in deployment.text,
                f"{name} must expose its mTLS application listener on 8443")
        require("containerPort: 9090" in deployment.text and "name: admin" in deployment.text,
                f"{name} must expose a separate health-only admin listener")
        require(deployment.text.count("port: admin") == 3,
                f"{name} startup, readiness, and liveness probes must use the admin listener")
        require("fsGroup: 65532" in deployment.text and "fsGroupChangePolicy: OnRootMismatch" in deployment.text,
                f"{name} must make read-only projected credentials available to the non-root process")

        required_env = {
            "AEGIS_PUBLIC_URL": EXPECTED_PUBLIC_URLS[name],
            "AEGIS_TLS_CERT_FILE": "/var/run/secrets/aegissre/tls/tls.crt",
            "AEGIS_TLS_KEY_FILE": "/var/run/secrets/aegissre/tls/tls.key",
            "AEGIS_TLS_CA_FILE": "/var/run/secrets/aegissre/trust/ca.crt",
            "AEGIS_TLS_IDENTITY": EXPECTED_IDENTITIES[name],
        }
        for variable, expected_value in required_env.items():
            block = env_block(deployment.text, variable)
            require(f"value: {expected_value}" in block,
                    f"{name} {variable} must equal {expected_value!r}")
        require("mountPath: /var/run/secrets/aegissre/tls" in deployment.text and
                "mountPath: /var/run/secrets/aegissre/trust" in deployment.text,
                f"{name} must mount leaf and trust material")
        require(f"secretName: {name}-tls" in deployment.text,
                f"{name} must use its own leaf certificate Secret")
        require("secretName: aegis-mtls-ca" in deployment.text,
                f"{name} must use the bounded AegisSRE trust bundle")

    database_consumers = {
        "aegis-monitor": "aegis-monitor-postgres",
        "aegis-operator": "aegis-operator-postgres",
        "aegis-mcp-action": "aegis-mcp-action-postgres",
    }
    for name, deployment in deployments.items():
        database_block = env_block(deployment.text, "AEGIS_DATABASE_URL_FILE")
        require(not env_block(deployment.text, "AEGIS_DATABASE_URL"),
                f"{name} must not receive a PostgreSQL credential through the process environment")
        if name in database_consumers:
            require("value: /var/run/secrets/aegissre/database/url" in database_block,
                    f"{name} must read its PostgreSQL URL from the mounted file")
            require("mountPath: /var/run/secrets/aegissre/database" in deployment.text,
                    f"{name} must mount database credentials read-only")
            require("fieldPath: metadata.uid" in env_block(deployment.text, "AEGIS_INSTANCE_ID"),
                    f"{name} must derive its durable-state lease identity from the Pod UID")
            require(f"name: {database_consumers[name]}" in deployment.text and
                    "name: aegis-postgres-ca" in deployment.text and
                    deployment.text.count("optional: false") >= 4,
                    f"{name} database URL or CA projection is not fail closed")
        else:
            require(not database_block and "/var/run/secrets/aegissre/database" not in deployment.text,
                    f"{name} was unnecessarily given durable-state credentials")

    delegation_file_variables = {
        "aegis-monitor": (
            "AEGIS_DELEGATION_PRIVATE_KEY_FILE",
            "/var/run/secrets/aegissre/signing/private-key",
            "aegis-monitor-signing",
        ),
        "aegis-operator": (
            "AEGIS_DELEGATION_PUBLIC_KEYRING_FILE",
            "/var/run/secrets/aegissre/signing/trusted-public-keys.json",
            "aegis-delegation-keyring",
        ),
        "aegis-mcp-action": (
            "AEGIS_DELEGATION_PUBLIC_KEYRING_FILE",
            "/var/run/secrets/aegissre/signing/trusted-public-keys.json",
            "aegis-delegation-keyring",
        ),
    }
    policy_consumers = set(delegation_file_variables) | {"aegis-mcp-read"}
    for deployment_name, (variable, expected_path, expected_secret) in delegation_file_variables.items():
        if deployment_name not in deployments:
            continue
        block = env_block(deployments[deployment_name].text, variable)
        require(bool(block), f"{deployment_name} must reference {variable}")
        require(f"value: {expected_path}" in block,
                f"{deployment_name} must read delegation material from the expected file")
        require(f"secretName: {expected_secret}" in deployments[deployment_name].text and
                "optional: false" in deployments[deployment_name].text,
                f"{deployment_name} must fail closed when delegation material is absent")
    for deployment_name in policy_consumers:
        if deployment_name not in deployments:
            continue
        policy_block = env_block(deployments[deployment_name].text, "AEGIS_WORKLOAD_POLICY_FILE")
        require("value: /etc/aegissre/policy/policy.json" in policy_block,
                f"{deployment_name} must use the mounted exact workload policy")
        require("mountPath: /etc/aegissre/policy" in deployments[deployment_name].text,
                f"{deployment_name} workload policy volume is not mounted")
        require("name: aegis-workload-policy" in deployments[deployment_name].text,
                f"{deployment_name} must reference the exact workload policy ConfigMap")
    for name, deployment in deployments.items():
        require(not env_block(deployment.text, "AEGIS_DELEGATION_PRIVATE_KEY"),
                f"legacy private-key environment injection remains in {name}")
        require(not env_block(deployment.text, "AEGIS_DELEGATION_PUBLIC_KEY"),
                f"legacy public-key environment injection remains in {name}")
        if name != "aegis-monitor":
            require(not env_block(deployment.text, "AEGIS_DELEGATION_PRIVATE_KEY_FILE"),
                    f"private signing key leaked into {name}")
        if name not in {"aegis-operator", "aegis-mcp-action"}:
            require(not env_block(deployment.text, "AEGIS_DELEGATION_PUBLIC_KEYRING_FILE"),
                    f"delegation verification keyring was unnecessarily exposed to {name}")
        if name not in policy_consumers:
            require("AEGIS_WORKLOAD_POLICY_FILE" not in deployment.text,
                    f"workload policy was unnecessarily exposed to {name}")

    for name, service in sorted(services.items()):
        require("type: ClusterIP" in service.text, f"{name} must remain ClusterIP-only")
        require("nodePort:" not in service.text and "externalIPs:" not in service.text,
                f"{name} exposes a node or external address")
        require("appProtocol: https" in service.text and "port: 8443" in service.text and
                "targetPort: https" in service.text,
                f"{name} Service must expose only the mTLS listener")

    for name, policy in network_policies.items():
        if name.endswith("-ingress") and name != "aegis-default-deny":
            require("port: 8443" in policy.text and "port: 8080" not in policy.text,
                    f"{name} must permit only the mTLS application port")
        if name in {"aegis-monitor-egress", "aegis-investigator-egress", "aegis-operator-egress"}:
            require("port: 8443" in policy.text and "port: 8080" not in policy.text,
                    f"{name} must permit only the mTLS application port")
        require("0.0.0.0/0" not in policy.text and "::/0" not in policy.text,
                f"{name} contains broad Internet egress")

    exact_peer_graph = {
        "aegis-investigator-ingress": ("aegis-investigator", {"aegis-monitor"}, "Ingress"),
        "aegis-operator-ingress": ("aegis-operator", {"aegis-monitor"}, "Ingress"),
        "aegis-mcp-read-ingress": ("aegis-mcp-read", {"aegis-monitor", "aegis-investigator"}, "Ingress"),
        "aegis-mcp-action-ingress": ("aegis-mcp-action", {"aegis-operator"}, "Ingress"),
        "aegis-monitor-egress": ("aegis-monitor", {"aegis-investigator", "aegis-operator", "aegis-mcp-read"}, "Egress"),
        "aegis-investigator-egress": ("aegis-investigator", {"aegis-mcp-read"}, "Egress"),
        "aegis-operator-egress": ("aegis-operator", {"aegis-mcp-action"}, "Egress"),
    }
    for name, (selected, peers, direction) in exact_peer_graph.items():
        policy = network_policies.get(name)
        if not policy:
            continue
        observed_names = set(re.findall(
            r"(?<![a-z0-9-])(aegis-(?:monitor|investigator|operator|mcp-read|mcp-action))(?![a-z0-9-])",
            policy.text,
        ))
        require(observed_names == peers | {selected} and
                policy.text.count("port: 8443") == 1 and
                policy.text.count(f"- {direction}") == 1 and
                "namespaceSelector:" not in policy.text and "ipBlock:" not in policy.text,
                f"{name} differs from the exact authenticated agent peer graph")

    kube_api_policy = network_policies.get("aegis-mcp-kubernetes-api-egress")
    if kube_api_policy:
        require("cidr: 10.43.0.1/32" in kube_api_policy.text and
                kube_api_policy.text.count("port: 443") == 1 and
                set(re.findall(r"- (aegis-mcp-(?:read|action))", kube_api_policy.text)) ==
                {"aegis-mcp-read", "aegis-mcp-action"} and
                "namespaceSelector:" not in kube_api_policy.text,
                "Kubernetes API egress must be the exact k3s service IP and two MCP workloads")
    default_deny = network_policies.get("aegis-default-deny")
    if default_deny:
        require("Ingress" in all_list_values(default_deny.text, "policyTypes") and
                "Egress" in all_list_values(default_deny.text, "policyTypes") and
                "ingress:" not in default_deny.text and "egress:" not in default_deny.text,
                "default-deny policy must isolate both directions without allow rules")
    dns_policy = network_policies.get("aegis-dns-egress")
    if dns_policy:
        require("kubernetes.io/metadata.name: kube-system" in dns_policy.text and
                "k8s-app: kube-dns" in dns_policy.text and
                dns_policy.text.count("port: 53") == 2,
                "DNS egress must be confined to CoreDNS on TCP and UDP 53")
    telemetry_policy = network_policies.get("aegis-mcp-read-telemetry-egress")
    if telemetry_policy:
        for instance, port in (("victoria-metrics", 8428), ("victoria-logs", 9428),
                               ("victoria-traces", 10428)):
            require(f"app.kubernetes.io/instance: {instance}" in telemetry_policy.text and
                    f"port: {port}" in telemetry_policy.text,
                    f"read MCP egress is missing the exact {instance} endpoint")
        require(telemetry_policy.text.count("kubernetes.io/metadata.name: observability") == 3,
                "each telemetry backend egress peer must intersect the observability namespace")
    otlp_policy = network_policies.get("aegis-otlp-egress")
    if otlp_policy:
        require("kubernetes.io/metadata.name: observability" in otlp_policy.text and
                "app.kubernetes.io/name: opentelemetry-collector" in otlp_policy.text and
                "app.kubernetes.io/instance: otel-collector" in otlp_policy.text and
                "port: 4318" in otlp_policy.text,
                "OTLP egress must be confined to the observability collector on TCP/4318")
    postgres_policy = network_policies.get("aegis-postgres-egress")
    if postgres_policy:
        for consumer in (*database_consumers, "aegis-postgres-migrate"):
            require(f"- {consumer}" in postgres_policy.text,
                    f"PostgreSQL egress selector is missing {consumer}")
        require("kubernetes.io/metadata.name: aegissre-data" in postgres_policy.text and
                "cnpg.io/cluster: aegis-postgres" in postgres_policy.text and
                "port: 5432" in postgres_policy.text,
                "PostgreSQL egress must be confined to the named data cluster on TCP/5432")

    if jobs:
        migration_name, migration = next(iter(jobs.items()))
        migration_images = [scalar_value(value) for value in
                            re.findall(r"(?m)^\s*image:\s*([^#\r\n]+)", migration.text)]
        require(len(migration_images) == 1 and bool(IMAGE_PATTERN.fullmatch(migration_images[0])),
                "migration Job image must be pinned by sha256 digest")
        if args.expected_image and migration_images:
            require(migration_images[0] == args.expected_image,
                    "migration Job image differs from the expected release artifact")
        if args.expected_migration_name:
            require(migration_name == args.expected_migration_name,
                    "migration Job name differs from the expected immutable release ID")
        if args.profile == "release" and migration_images:
            require(not migration_images[0].endswith("@" + ZERO_DIGEST),
                    "migration Job still uses the non-pullable zero digest")
            require("replace-before-live" not in migration_name,
                    "release migration Job name still uses the release sentinel")
        require("- /usr/local/bin/aegissre" in migration.text and "- migrate" in migration.text,
                "migration Job must invoke the bounded migrate subcommand")
        require("automountServiceAccountToken: false" in migration.text and
                "restartPolicy: Never" in migration.text and "enableServiceLinks: false" in migration.text,
                "migration Job runtime isolation is incomplete")
        require("value: /var/run/secrets/aegissre/database/url" in
                env_block(migration.text, "AEGIS_DATABASE_URL_FILE"),
                "migration Job must read its role-specific URL from a file")
        require("name: aegis-postgres-migration" in migration.text and
                "name: aegis-postgres-ca" in migration.text and
                migration.text.count("optional: false") >= 2,
                "migration Job database URL or CA projection is not fail closed")
        require("readOnlyRootFilesystem: true" in migration.text and "allowPrivilegeEscalation: false" in migration.text,
                "migration Job container security context is incomplete")

    read_role = roles.get("aegis-mcp-read")
    action_role = roles.get("aegis-mcp-action")
    if read_role:
        require(normalized_role_rules(read_role.text) == {
            (("",), ("pods",), ("get", "list"), ()),
            (("",), ("pods/log",), ("get",), ()),
            (("",), ("events",), ("list",), ()),
            (("apps",), ("deployments",), ("get",), (args.expected_target,)),
            (("apps",), ("replicasets",), ("get",), ()),
        }, "read MCP Role differs from its exact observation and owner-proof permissions")
    if action_role:
        require(all_list_values(action_role.text, "resourceNames") == [args.expected_target],
                "action MCP must be confined to the exact expected workload")
        require(set(all_list_values(action_role.text, "resources")) == {"deployments"},
                "action MCP may access only Deployments")
        require(set(all_list_values(action_role.text, "verbs")) == {"get", "patch"},
                "action MCP verbs must be exactly get and patch")
        require("*" not in action_role.text, "action MCP Role contains a wildcard")

    if args.profile == "release":
        require(args.expected_target != "replace-before-live", "release still uses the workload target sentinel")

    policy_document = None
    policy_config_name = ""
    for candidate in config_maps:
        raw_policy = literal_block(candidate.text, "policy.json")
        if not raw_policy:
            continue
        try:
            policy_document = json.loads(raw_policy)
        except json.JSONDecodeError:
            errors.append("mounted workload policy is not valid JSON")
        require("namespace: outage-arena" in candidate.text,
                "generated workload policy ConfigMap must be in outage-arena")
        policy_config_name = candidate.name
        break
    require(isinstance(policy_document, dict), "generated workload policy ConfigMap was not found")
    if isinstance(policy_document, dict):
        require(policy_document.get("schema_version") == "aegissre.io/workload-policy/v1",
                "workload policy schema version is not v1")
        require(bool(policy_document.get("policy_id")), "workload policy ID is required")
        workloads = policy_document.get("workloads", [])
        require(isinstance(workloads, list) and len(workloads) == 1,
                "release overlay must authorize exactly one workload")
        if isinstance(workloads, list) and len(workloads) == 1 and isinstance(workloads[0], dict):
            workload = workloads[0]
            target = workload.get("target", {})
            require(target == {
                "api_version": "apps/v1",
                "kind": "Deployment",
                "namespace": "outage-arena",
                "name": args.expected_target,
            }, "mounted workload policy target differs from RBAC and the expected target")
            require(workload.get("allowed_actions") == ["restart_deployment"],
                    "acceptance policy must allow only restart_deployment")
            require(workload.get("allowed_signal_sources") == ["metrics"],
                    "acceptance policy must allow only collector-independent metric triggers")
            require(workload.get("maximum_replicas") == 1 and workload.get("maximum_replica_increase") == 1,
                    "acceptance policy replica bounds must remain one")
    if policy_config_name:
        for deployment_name in policy_consumers:
            if deployment_name in deployments:
                require(f"name: {policy_config_name}" in deployments[deployment_name].text,
                        f"{deployment_name} does not reference the generated workload policy ConfigMap")

    config = None
    for candidate in config_maps:
        candidate_data = mapping(candidate.text, "data")
        if "AEGIS_DRY_RUN" in candidate_data:
            config = candidate_data
            break
    require(config is not None, "generated aegis-config ConfigMap was not found")
    if config is not None:
        require(config.get("AEGIS_DRY_RUN") == str(args.expected_dry_run).lower(),
                "AEGIS_DRY_RUN does not match the selected release profile")
        require(config.get("AEGIS_ALLOW_MUTATIONS") == str(args.expected_mutations).lower(),
                "AEGIS_ALLOW_MUTATIONS does not match the selected release profile")
        require(config.get("AEGIS_WHATSAPP_ENABLED") == "false",
                "WhatsApp must remain disabled until a restricted egress overlay exists")
        require(config.get("AEGIS_ALLOW_LOG_TRACE_ACTIONS") == "false",
                "log/trace-triggered writes must remain disabled until live provenance is proven")
        require(config.get("AEGIS_MTLS_ENABLED") == "true",
                "mTLS must be mandatory in every production-derived profile")
        require(config.get("AEGIS_LISTEN_ADDR") == ":8443" and
                config.get("AEGIS_ADMIN_LISTEN_ADDR") == ":9090",
                "application and health listeners must remain separated")
        require(config.get("AEGIS_TRUST_DOMAIN") == "aegissre.internal" and
                config.get("AEGIS_SYSTEM_NAMESPACE") == "outage-arena",
                "workload identity scope differs from the mounted certificate identities")
        require(config.get("AEGIS_OBSERVE_MCP_URL") == "https://aegis-mcp-read:8443/mcp" and
                config.get("AEGIS_OPERATE_MCP_URL") == "https://aegis-mcp-action:8443/mcp" and
                config.get("AEGIS_INVESTIGATOR_URL") == "https://aegis-investigator:8443" and
                config.get("AEGIS_OPERATOR_URL") == "https://aegis-operator:8443",
                "an internal action or coordination endpoint is not pinned to HTTPS")
        require(config.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") ==
                "http://otel-collector.observability.svc.cluster.local:4318/v1/traces" and
                config.get("OTEL_EXPORTER_OTLP_PROTOCOL") == "http/protobuf",
                "OTLP trace export must use the in-cluster collector HTTP endpoint")
        require(config.get("AEGIS_DATABASE_MAX_CONNECTIONS") == "8" and
                config.get("AEGIS_STATE_LEASE") == "1m" and
                config.get("AEGIS_OUTBOX_POLL_INTERVAL") == "2s" and
                config.get("AEGIS_OUTBOX_MAX_ATTEMPTS") == "8",
                "durable-state pool, lease, or outbox bounds differ from the reviewed profile")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlay", type=pathlib.Path, required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-dry-run", type=parse_bool, required=True)
    parser.add_argument("--expected-mutations", type=parse_bool, required=True)
    parser.add_argument("--expected-image", type=image_reference)
    parser.add_argument("--expected-migration-name")
    parser.add_argument("--profile", choices=("scaffold", "release"), default="scaffold")
    args = parser.parse_args()

    try:
        rendered = rendered_overlay(args.overlay)
        documents = split_documents(rendered)
        errors = validate(args, documents)
    except (OSError, RuntimeError) as error:
        print(f"manifest policy: {error}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"manifest policy: {error}", file=sys.stderr)
        return 1
    print(
        f"manifest policy passed: overlay={args.overlay} profile={args.profile} "
        f"target={args.expected_target}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
