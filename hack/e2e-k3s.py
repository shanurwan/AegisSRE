#!/usr/bin/env python3
"""Opt-in live k3s acceptance test for the single authorized canary.

Without --execute the command performs read-only preflight and prints the exact
scope. Preflight validates Secret projections and workload readiness without
reading Secret objects or data. With --execute it creates one intentionally
unready Deployment, waits for AegisSRE to restart only that Deployment, verifies
recovery and terminal-report logging, and retains the canary as evidence. It
never deploys AegisSRE itself or deletes a workload.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass


EXPECTED_CONTEXT = "laboratory"
EXPECTED_NAMESPACE = "outage-arena"
EXPECTED_CANARY = "aegissre-e2e-canary"
ACKNOWLEDGEMENT = "I_ACKNOWLEDGE_AEGISSRE_CANARY_MUTATION"
ZERO_DIGEST = "sha256:" + "0" * 64
IMAGE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
RUN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
AegisDeployments = (
    "aegis-monitor",
    "aegis-investigator",
    "aegis-operator",
    "aegis-mcp-read",
    "aegis-mcp-action",
)
EXPECTED_NETWORK_POLICIES = frozenset({
    "aegis-default-deny",
    "aegis-investigator-ingress",
    "aegis-operator-ingress",
    "aegis-mcp-read-ingress",
    "aegis-mcp-action-ingress",
    "aegis-dns-egress",
    "aegis-monitor-egress",
    "aegis-investigator-egress",
    "aegis-operator-egress",
    "aegis-mcp-kubernetes-api-egress",
    "aegis-mcp-read-telemetry-egress",
    "aegis-otlp-egress",
    "aegis-postgres-egress",
})
POLICY_CONSUMERS = {
    "aegis-monitor",
    "aegis-operator",
    "aegis-mcp-read",
    "aegis-mcp-action",
}
POLICY_PATH = "/etc/aegissre/policy/policy.json"
EXPECTED_IDENTITIES = {
    name: f"spiffe://aegissre.internal/ns/{EXPECTED_NAMESPACE}/sa/{name}"
    for name in AegisDeployments
}


class AcceptanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class Scope:
    context: str
    namespace: str
    canary: str


def invoke(command: list[str], *, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, input=stdin, capture_output=True, text=True, check=False)
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit code {completed.returncode}"
        raise AcceptanceError(f"command failed ({' '.join(command[:4])} ...): {detail}")
    return completed


def kubectl(scope: Scope, arguments: list[str], *, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return invoke(
        ["kubectl", "--context", scope.context, "--namespace", scope.namespace, *arguments],
        stdin=stdin,
        check=check,
    )


def kube_json(scope: Scope, arguments: list[str]) -> dict:
    completed = kubectl(scope, [*arguments, "-o", "json"])
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AcceptanceError("kubectl returned malformed JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError("kubectl JSON response was not an object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def deployment_image(deployment: dict) -> str:
    containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    require(len(containers) == 1, "each AegisSRE Deployment must contain exactly one container")
    image = containers[0].get("image", "")
    require(bool(IMAGE_PATTERN.fullmatch(image)), "every running AegisSRE image must use a sha256 digest")
    require(not image.endswith("@" + ZERO_DIGEST), "a running AegisSRE Deployment uses the zero-digest sentinel")
    return image


def deployment_available(deployment: dict) -> bool:
    desired = deployment.get("spec", {}).get("replicas", 1)
    status = deployment.get("status", {})
    return (
        status.get("observedGeneration", 0) >= deployment.get("metadata", {}).get("generation", 0)
        and status.get("availableReplicas", 0) >= desired
    )


def normalized_role_rules(role: dict) -> set[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]]:
    return {
        (
            tuple(sorted(rule.get("apiGroups", []))),
            tuple(sorted(rule.get("resources", []))),
            tuple(sorted(rule.get("verbs", []))),
            tuple(sorted(rule.get("resourceNames", []))),
        )
        for rule in role.get("rules", [])
    }


def validate_mcp_role(role: dict, scope: Scope, name: str) -> None:
    metadata = role.get("metadata", {})
    require(role.get("apiVersion") == "rbac.authorization.k8s.io/v1" and role.get("kind") == "Role" and
            metadata.get("name") == name and metadata.get("namespace") == scope.namespace,
            f"{name} Role identity or namespace differs from the live scope")
    if name == "aegis-mcp-action":
        expected = {
            (("apps",), ("deployments",), ("get", "patch"), (scope.canary,)),
        }
    else:
        require(name == "aegis-mcp-read", "unexpected MCP Role name")
        expected = {
            (("",), ("pods",), ("get", "list"), ()),
            (("",), ("pods/log",), ("get",), ()),
            (("",), ("events",), ("list",), ()),
            (("apps",), ("deployments",), ("get",), (scope.canary,)),
            (("apps",), ("replicasets",), ("get",), ()),
        }
    rules = role.get("rules")
    require(isinstance(rules, list) and len(rules) == len(expected) and
            all(isinstance(rule, dict) and
                {"apiGroups", "resources", "verbs"} <= set(rule) <= {
                    "apiGroups", "resources", "resourceNames", "verbs",
                } for rule in rules),
            f"{name} runtime Role has duplicate or malformed rules")
    require(normalized_role_rules(role) == expected,
            f"{name} runtime Role differs from its exact reviewed authority")


def only_container(deployment: dict) -> dict:
    containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    require(len(containers) == 1, "each AegisSRE Deployment must contain exactly one container")
    return containers[0]


def environment(container: dict) -> dict[str, str]:
    values: dict[str, str] = {}
    seen: set[str] = set()
    for entry in container.get("env", []):
        name = entry.get("name", "")
        require(bool(name) and name not in seen, "container has an unnamed or duplicate environment variable")
        seen.add(name)
        if "value" in entry:
            values[name] = str(entry["value"])
    return values


def mounted_secret(deployment: dict, mount_path: str) -> tuple[str, dict[str, str]]:
    pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
    container = only_container(deployment)
    mounts = [entry for entry in container.get("volumeMounts", []) if entry.get("mountPath") == mount_path]
    require(len(mounts) == 1 and mounts[0].get("readOnly") is True,
            f"{mount_path} must be mounted exactly once and read-only")
    volumes = [entry for entry in pod_spec.get("volumes", []) if entry.get("name") == mounts[0].get("name")]
    require(len(volumes) == 1, f"{mount_path} does not resolve to exactly one volume")
    secret = volumes[0].get("secret", {})
    require(secret.get("optional") is False, f"{mount_path} Secret must be required")
    require(secret.get("defaultMode") == 288, f"{mount_path} Secret projection must use mode 0440")
    secret_name = secret.get("secretName", "")
    require(bool(secret_name), f"{mount_path} is not sourced from a Secret")
    items: dict[str, str] = {}
    for item in secret.get("items", []):
        key = item.get("key", "")
        path = item.get("path", "")
        require(bool(key) and bool(path) and key not in items,
                f"{mount_path} Secret projection has a duplicate or invalid key/path")
        items[key] = path
    require(bool(items), f"{mount_path} Secret projection has no bounded items")
    return secret_name, items


def mounted_projected_secrets(deployment: dict, mount_path: str) -> dict[str, dict[str, str]]:
    pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
    container = only_container(deployment)
    mounts = [entry for entry in container.get("volumeMounts", []) if entry.get("mountPath") == mount_path]
    require(len(mounts) == 1 and mounts[0].get("readOnly") is True,
            f"{mount_path} must be mounted exactly once and read-only")
    volumes = [entry for entry in pod_spec.get("volumes", []) if entry.get("name") == mounts[0].get("name")]
    require(len(volumes) == 1, f"{mount_path} does not resolve to exactly one volume")
    projected = volumes[0].get("projected", {})
    require(projected.get("defaultMode") == 288, f"{mount_path} projection must use mode 0440")
    result: dict[str, dict[str, str]] = {}
    for source in projected.get("sources", []):
        secret = source.get("secret", {})
        name = secret.get("name", "")
        require(bool(name) and name not in result and secret.get("optional") is False,
                f"{mount_path} contains a duplicate, unnamed, or optional Secret")
        items: dict[str, str] = {}
        for item in secret.get("items", []):
            key = item.get("key", "")
            path = item.get("path", "")
            require(bool(key) and bool(path) and key not in items,
                    f"{mount_path} Secret projection contains a duplicate or invalid key/path")
            items[key] = path
        require(bool(items), f"{mount_path} Secret projection has no bounded items")
        result[name] = items
    require(bool(result), f"{mount_path} is not sourced from projected Secrets")
    return result


def validate_runtime_transport(scope: Scope, deployments: dict[str, dict]) -> None:
    # Inspect the pod projection contract only. Preflight intentionally never
    # obtains the referenced Secret objects or their data.
    for name, deployment in deployments.items():
        pod_template = deployment.get("spec", {}).get("template", {})
        pod_spec = pod_template.get("spec", {})
        container = only_container(deployment)
        env = environment(container)
        annotations = pod_template.get("metadata", {}).get("annotations", {})
        require(annotations.get("aegissre.io/transport-assurance") == "authenticated-encrypted",
                f"{name} does not declare authenticated encrypted transport")
        require(pod_spec.get("securityContext", {}).get("fsGroup") == 65532,
                f"{name} cannot read projected credentials as its non-root group")

        ports = {entry.get("name"): entry.get("containerPort") for entry in container.get("ports", [])}
        require(ports == {"https": 8443, "admin": 9090},
                f"{name} does not expose the exact application/admin port split")
        for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
            require(container.get(probe_name, {}).get("httpGet", {}).get("port") == "admin",
                    f"{name} {probe_name} is not isolated on the admin listener")

        expected_env = {
            "AEGIS_PUBLIC_URL": f"https://{name}:8443",
            "AEGIS_TLS_CERT_FILE": "/var/run/secrets/aegissre/tls/tls.crt",
            "AEGIS_TLS_KEY_FILE": "/var/run/secrets/aegissre/tls/tls.key",
            "AEGIS_TLS_CA_FILE": "/var/run/secrets/aegissre/trust/ca.crt",
            "AEGIS_TLS_IDENTITY": EXPECTED_IDENTITIES[name],
        }
        for variable, expected in expected_env.items():
            require(env.get(variable) == expected, f"{name} {variable} does not match its runtime identity")

        leaf_name, leaf_items = mounted_secret(deployment, "/var/run/secrets/aegissre/tls")
        require(leaf_name == f"{name}-tls" and leaf_items == {
            "tls.crt": "tls.crt",
            "tls.key": "tls.key",
        },
                f"{name} does not use its own exact leaf certificate projection")
        trust_name, trust_items = mounted_secret(deployment, "/var/run/secrets/aegissre/trust")
        require(trust_name == "aegis-mtls-ca" and trust_items == {"ca.crt": "ca.crt"},
                f"{name} does not use the bounded AegisSRE trust bundle")

        service = kube_json(scope, ["get", "service", name])
        service_ports = service.get("spec", {}).get("ports", [])
        require(service.get("spec", {}).get("type") == "ClusterIP" and service_ports == [{
            "appProtocol": "https",
            "name": "https",
            "port": 8443,
            "protocol": "TCP",
            "targetPort": "https",
        }], f"{name} Service does not expose exactly the mTLS application listener")


def validate_runtime_delegation(deployments: dict[str, dict]) -> None:
    monitor_env = environment(only_container(deployments["aegis-monitor"]))
    require("AEGIS_DELEGATION_PRIVATE_KEY" not in monitor_env,
            "Monitor still receives its signing key through the process environment")
    require(monitor_env.get("AEGIS_DELEGATION_PRIVATE_KEY_FILE") ==
            "/var/run/secrets/aegissre/signing/private-key",
            "Monitor does not use the file-mounted delegation signing key")
    signing_name, signing_items = mounted_secret(
        deployments["aegis-monitor"], "/var/run/secrets/aegissre/signing"
    )
    require(signing_name == "aegis-monitor-signing" and signing_items == {"private-key": "private-key"},
            "Monitor signing Secret projection is not least privilege")

    for name in ("aegis-operator", "aegis-mcp-action"):
        env = environment(only_container(deployments[name]))
        require("AEGIS_DELEGATION_PUBLIC_KEY" not in env,
                f"{name} still receives a verifier key through the process environment")
        require(env.get("AEGIS_DELEGATION_PUBLIC_KEYRING_FILE") ==
                "/var/run/secrets/aegissre/signing/trusted-public-keys.json",
                f"{name} does not use the rotation-safe verifier keyring")
        keyring_name, keyring_items = mounted_secret(deployments[name], "/var/run/secrets/aegissre/signing")
        require(keyring_name == "aegis-delegation-keyring" and keyring_items == {
            "trusted-public-keys.json": "trusted-public-keys.json",
        },
                f"{name} verifier Secret projection is not least privilege")


def validate_runtime_database(deployments: dict[str, dict]) -> None:
    database_consumers = {
        "aegis-monitor": "aegis-monitor-postgres",
        "aegis-operator": "aegis-operator-postgres",
        "aegis-mcp-action": "aegis-mcp-action-postgres",
    }
    for name, deployment in deployments.items():
        container = only_container(deployment)
        env = environment(container)
        env_entries = {entry.get("name"): entry for entry in container.get("env", [])}
        require("AEGIS_DATABASE_URL" not in env_entries,
                f"{name} still receives its database credential through the process environment")
        if name not in database_consumers:
            require("AEGIS_DATABASE_URL_FILE" not in env_entries,
                    f"{name} was unnecessarily given durable-state credentials")
            continue

        require(env.get("AEGIS_DATABASE_URL_FILE") == "/var/run/secrets/aegissre/database/url",
                f"{name} does not read its PostgreSQL URL from the mounted file")
        instance = env_entries.get("AEGIS_INSTANCE_ID", {})
        require(instance.get("valueFrom", {}).get("fieldRef", {}).get("fieldPath") == "metadata.uid",
                f"{name} durable-state lease identity is not derived from its Pod UID")
        expected_projection = {
            database_consumers[name]: {"url": "url"},
            "aegis-postgres-ca": {"ca.crt": "ca.crt"},
        }
        require(mounted_projected_secrets(deployment, "/var/run/secrets/aegissre/database") ==
                expected_projection, f"{name} database projection differs from the least-privilege contract")


def selector_names(selector: dict) -> set[str]:
    if not isinstance(selector, dict):
        return set()
    labels = selector.get("matchLabels")
    if set(selector) == {"matchLabels"} and isinstance(labels, dict) and \
            set(labels) == {"app.kubernetes.io/name"}:
        return {labels["app.kubernetes.io/name"]}
    expressions = selector.get("matchExpressions")
    if set(selector) == {"matchExpressions"} and isinstance(expressions, list) and len(expressions) == 1:
        expression = expressions[0]
        if isinstance(expression, dict) and set(expression) == {"key", "operator", "values"} and \
                expression.get("key") == "app.kubernetes.io/name" and expression.get("operator") == "In" and \
                isinstance(expression.get("values"), list) and \
                all(isinstance(value, str) and value for value in expression["values"]) and \
                len(expression["values"]) == len(set(expression["values"])):
            return set(expression["values"])
    return set()


def label_selector_matches(selector: dict, labels: dict[str, str]) -> bool:
    require(isinstance(selector, dict) and set(selector) <= {"matchLabels", "matchExpressions"},
            "NetworkPolicy podSelector has an invalid shape")
    match_labels = selector.get("matchLabels", {})
    expressions = selector.get("matchExpressions", [])
    require(isinstance(match_labels, dict) and
            all(isinstance(key, str) and key and isinstance(value, str)
                for key, value in match_labels.items()),
            "NetworkPolicy podSelector matchLabels are malformed")
    require(isinstance(expressions, list),
            "NetworkPolicy podSelector matchExpressions are malformed")
    for expression in expressions:
        require(isinstance(expression, dict) and
                {"key", "operator"} <= set(expression) <= {"key", "operator", "values"},
                "NetworkPolicy podSelector expression has an invalid shape")
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values", [])
        require(isinstance(key, str) and key and operator in {
            "In", "NotIn", "Exists", "DoesNotExist",
        } and isinstance(values, list) and all(isinstance(value, str) for value in values),
                "NetworkPolicy podSelector expression is malformed")
        if operator in {"In", "NotIn"}:
            require(bool(values), "NetworkPolicy In/NotIn selector requires values")
        else:
            require(not values, "NetworkPolicy Exists/DoesNotExist selector cannot have values")
    for key, value in match_labels.items():
        if key not in labels or labels[key] != value:
            return False
    for expression in expressions:
        key = expression["key"]
        operator = expression["operator"]
        values = expression.get("values", [])
        if operator == "In" and (key not in labels or labels[key] not in values):
            return False
        if operator == "NotIn" and key in labels and labels[key] in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True


def load_runtime_network_policies(
        scope: Scope,
        deployments: dict[str, dict],
        expected_names: set[str] | frozenset[str] = EXPECTED_NETWORK_POLICIES,
) -> dict[str, dict]:
    require(set(deployments) == set(AegisDeployments),
            "NetworkPolicy validation did not receive the exact five Aegis Deployments")
    pod_label_sets: list[dict[str, str]] = []
    for name in AegisDeployments:
        labels = deployments[name].get("spec", {}).get("template", {}).get("metadata", {}).get("labels")
        require(isinstance(labels, dict) and labels and
                all(isinstance(key, str) and key and isinstance(value, str)
                    for key, value in labels.items()),
                f"{name} Pod labels are malformed")
        pod_label_sets.append(labels)

    listing = kube_json(scope, ["get", "networkpolicies"])
    require(listing.get("apiVersion") == "networking.k8s.io/v1" and
            listing.get("kind") == "NetworkPolicyList" and isinstance(listing.get("items"), list),
            "Kubernetes NetworkPolicy list shape is invalid")
    policies: dict[str, dict] = {}
    for policy in listing["items"]:
        require(isinstance(policy, dict) and policy.get("apiVersion") == "networking.k8s.io/v1" and
                policy.get("kind") == "NetworkPolicy",
                "Kubernetes NetworkPolicy list contains a malformed object")
        metadata = policy.get("metadata", {})
        name = metadata.get("name")
        require(isinstance(name, str) and name and metadata.get("namespace") == scope.namespace,
                "NetworkPolicy identity or namespace differs from the live scope")
        require(name not in policies, f"NetworkPolicy list contains duplicate name {name}")
        spec = policy.get("spec")
        require(isinstance(spec, dict) and isinstance(spec.get("podSelector"), dict),
                f"NetworkPolicy {name} has a malformed spec or podSelector")
        policies[name] = policy

    missing = set(expected_names) - set(policies)
    require(not missing,
            "required NetworkPolicies are absent: " + ", ".join(sorted(missing)))
    for name, policy in policies.items():
        if name in expected_names:
            continue
        selector = policy["spec"]["podSelector"]
        require(not any(label_selector_matches(selector, labels) for labels in pod_label_sets),
                f"unexpected additive NetworkPolicy {name} selects an Aegis workload")
    return policies


def require_policy_direction(spec: dict, name: str, policy_types: list[str]) -> None:
    require(spec.get("policyTypes") == policy_types,
            f"{name} policyTypes differ from the exact expected direction")
    if policy_types == ["Ingress"]:
        require("egress" not in spec, f"{name} unexpectedly contains egress rules")
    elif policy_types == ["Egress"]:
        require("ingress" not in spec, f"{name} unexpectedly contains ingress rules")
    else:
        require(policy_types == ["Ingress", "Egress"] and
                "ingress" not in spec and "egress" not in spec,
                f"{name} is not an exact bidirectional default deny")


def validate_kubernetes_api_egress(spec: dict) -> None:
    name = "aegis-mcp-kubernetes-api-egress"
    require_policy_direction(spec, name, ["Egress"])
    require(spec.get("podSelector") == {"matchExpressions": [{
        "key": "app.kubernetes.io/name",
        "operator": "In",
        "values": ["aegis-mcp-read", "aegis-mcp-action"],
    }]} and spec.get("egress") == [{
        "ports": [{"port": 443, "protocol": "TCP"}],
        "to": [{"ipBlock": {"cidr": "10.43.0.1/32"}}],
    }], "Kubernetes API egress is not confined to the exact MCP workloads and service IP")


def validate_runtime_network(scope: Scope, deployments: dict[str, dict]) -> None:
    policies = load_runtime_network_policies(scope, deployments)
    default_deny = policies["aegis-default-deny"]["spec"]
    require_policy_direction(default_deny, "aegis-default-deny", ["Ingress", "Egress"])
    require(default_deny.get("podSelector") == {
        "matchLabels": {"app.kubernetes.io/part-of": "aegissre"},
    },
            "live default-deny NetworkPolicy is not an exact bidirectional isolation boundary")

    ingress_graph = {
        "aegis-investigator-ingress": ("aegis-investigator", {"aegis-monitor"}),
        "aegis-operator-ingress": ("aegis-operator", {"aegis-monitor"}),
        "aegis-mcp-read-ingress": ("aegis-mcp-read", {"aegis-monitor", "aegis-investigator"}),
        "aegis-mcp-action-ingress": ("aegis-mcp-action", {"aegis-operator"}),
    }
    for policy_name, (destination, sources) in ingress_graph.items():
        spec = policies[policy_name]["spec"]
        require_policy_direction(spec, policy_name, ["Ingress"])
        rules = spec.get("ingress", [])
        require(selector_names(spec.get("podSelector", {})) == {destination} and len(rules) == 1 and
                len(rules[0].get("from", [])) == 1 and
                set(rules[0]["from"][0]) == {"podSelector"} and
                selector_names(rules[0]["from"][0].get("podSelector", {})) == sources and
                rules[0].get("ports") == [{"port": 8443, "protocol": "TCP"}],
                f"{policy_name} differs from the exact mTLS caller graph")

    egress_graph = {
        "aegis-monitor-egress": ("aegis-monitor", {"aegis-investigator", "aegis-operator", "aegis-mcp-read"}),
        "aegis-investigator-egress": ("aegis-investigator", {"aegis-mcp-read"}),
        "aegis-operator-egress": ("aegis-operator", {"aegis-mcp-action"}),
    }
    for policy_name, (source, destinations) in egress_graph.items():
        spec = policies[policy_name]["spec"]
        require_policy_direction(spec, policy_name, ["Egress"])
        rules = spec.get("egress", [])
        require(selector_names(spec.get("podSelector", {})) == {source} and len(rules) == 1 and
                len(rules[0].get("to", [])) == 1 and
                set(rules[0]["to"][0]) == {"podSelector"} and
                selector_names(rules[0]["to"][0].get("podSelector", {})) == destinations and
                rules[0].get("ports") == [{"port": 8443, "protocol": "TCP"}],
                f"{policy_name} differs from the exact mTLS destination graph")

    dns_spec = policies["aegis-dns-egress"]["spec"]
    require_policy_direction(dns_spec, "aegis-dns-egress", ["Egress"])
    dns = dns_spec.get("egress", [])
    require(dns_spec.get("podSelector") == {
        "matchLabels": {"app.kubernetes.io/part-of": "aegissre"},
    } and len(dns) == 1 and dns[0].get("ports") == [
        {"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"},
    ] and dns[0].get("to") == [{
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
    }], "DNS egress is not confined to CoreDNS")

    validate_kubernetes_api_egress(policies["aegis-mcp-kubernetes-api-egress"]["spec"])

    telemetry = policies["aegis-mcp-read-telemetry-egress"]["spec"]
    require_policy_direction(telemetry, "aegis-mcp-read-telemetry-egress", ["Egress"])
    require(selector_names(telemetry.get("podSelector", {})) == {"aegis-mcp-read"},
            "telemetry egress is not confined to read MCP")
    observed_telemetry: set[tuple[str, int]] = set()
    telemetry_rules = telemetry.get("egress", [])
    require(len(telemetry_rules) == 3, "telemetry egress must contain exactly three backend rules")
    for rule in telemetry_rules:
        peers = rule.get("to", [])
        ports = rule.get("ports", [])
        require(len(peers) == 1 and len(ports) == 1 and ports[0].get("protocol") == "TCP" and
                set(peers[0]) == {"namespaceSelector", "podSelector"} and
                peers[0].get("namespaceSelector", {}).get("matchLabels", {}) ==
                {"kubernetes.io/metadata.name": "observability"},
                "telemetry egress contains an unbounded peer or port")
        instance = peers[0].get("podSelector", {}).get("matchLabels", {}).get("app.kubernetes.io/instance", "")
        observed_telemetry.add((instance, int(ports[0].get("port", 0))))
    require(observed_telemetry == {
        ("victoria-metrics", 8428), ("victoria-logs", 9428), ("victoria-traces", 10428),
    }, "telemetry egress does not match the three exact Victoria backends")

    otlp = policies["aegis-otlp-egress"]["spec"]
    require_policy_direction(otlp, "aegis-otlp-egress", ["Egress"])
    require(otlp.get("podSelector") == {
        "matchLabels": {"app.kubernetes.io/part-of": "aegissre"},
    } and otlp.get("egress") == [{
                "ports": [{"port": 4318, "protocol": "TCP"}],
                "to": [{
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "observability"}},
                    "podSelector": {"matchLabels": {
                        "app.kubernetes.io/instance": "otel-collector",
                        "app.kubernetes.io/name": "opentelemetry-collector",
                    }},
                }],
            }], "OTLP egress is not confined to the in-cluster collector")

    postgres = policies["aegis-postgres-egress"]["spec"]
    require_policy_direction(postgres, "aegis-postgres-egress", ["Egress"])
    require(selector_names(postgres.get("podSelector", {})) == {
        "aegis-monitor", "aegis-operator", "aegis-mcp-action", "aegis-postgres-migrate",
    } and postgres.get("egress") == [{
        "ports": [{"port": 5432, "protocol": "TCP"}],
        "to": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "aegissre-data"}},
            "podSelector": {"matchLabels": {"cnpg.io/cluster": "aegis-postgres"}},
        }],
    }], "PostgreSQL egress is not confined to the named data cluster")


def workload_policy_config_name(deployment: dict) -> str:
    pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
    containers = pod_spec.get("containers", [])
    require(len(containers) == 1, "each AegisSRE Deployment must contain exactly one container")
    container = containers[0]

    policy_env = [entry for entry in container.get("env", []) if entry.get("name") == "AEGIS_WORKLOAD_POLICY_FILE"]
    require(len(policy_env) == 1 and policy_env[0].get("value") == POLICY_PATH,
            "action decision point must use the exact mounted workload policy path")

    mounts = [entry for entry in container.get("volumeMounts", []) if entry.get("mountPath") == "/etc/aegissre/policy"]
    require(len(mounts) == 1 and mounts[0].get("readOnly") is True,
            "workload policy must have one read-only volume mount")
    volume_name = mounts[0].get("name", "")
    require(bool(volume_name), "workload policy volume mount has no name")

    volumes = [entry for entry in pod_spec.get("volumes", []) if entry.get("name") == volume_name]
    require(len(volumes) == 1, "workload policy mount does not resolve to exactly one volume")
    config_name = volumes[0].get("configMap", {}).get("name", "")
    require(bool(config_name), "workload policy volume is not sourced from a ConfigMap")
    return config_name


def validate_runtime_workload_policy(scope: Scope, deployments: dict[str, dict]) -> None:
    policy_config_names = {
        workload_policy_config_name(deployments[name])
        for name in POLICY_CONSUMERS
    }
    require(len(policy_config_names) == 1,
            "Monitor, Operator, read MCP, and action MCP do not share one workload policy ConfigMap")

    for name in set(AegisDeployments) - POLICY_CONSUMERS:
        container = deployments[name].get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])[0]
        env_names = {entry.get("name") for entry in container.get("env", [])}
        mount_paths = {entry.get("mountPath") for entry in container.get("volumeMounts", [])}
        require("AEGIS_WORKLOAD_POLICY_FILE" not in env_names and "/etc/aegissre/policy" not in mount_paths,
                f"{name} must not receive action policy material")

    config_name = next(iter(policy_config_names))
    policy_text = kube_json(scope, ["get", "configmap", config_name]).get("data", {}).get("policy.json", "")
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError as error:
        raise AcceptanceError("mounted workload policy is not valid JSON") from error

    expected_target = {
        "api_version": "apps/v1",
        "kind": "Deployment",
        "namespace": scope.namespace,
        "name": scope.canary,
    }
    require(policy.get("schema_version") == "aegissre.io/workload-policy/v1",
            "mounted workload policy schema is not v1")
    require(bool(policy.get("policy_id")), "mounted workload policy has no policy ID")
    workloads = policy.get("workloads", [])
    require(isinstance(workloads, list) and len(workloads) == 1 and isinstance(workloads[0], dict),
            "mounted workload policy must authorize exactly one workload")
    workload = workloads[0]
    require(workload.get("target") == expected_target,
            "mounted workload policy target differs from the exact canary")
    require(workload.get("allowed_actions") == ["restart_deployment"],
            "mounted workload policy must allow only restart_deployment")
    require(workload.get("allowed_signal_sources") == ["metrics"],
            "mounted workload policy must allow only metric-triggered action")
    require(workload.get("maximum_replicas") == 1 and workload.get("maximum_replica_increase") == 1,
            "mounted workload policy replica bounds must remain one")


def validate_runtime_service_accounts(deployments: dict[str, dict]) -> None:
    for name in AegisDeployments:
        pod_spec = deployments[name].get("spec", {}).get("template", {}).get("spec", {})
        require(pod_spec.get("serviceAccountName") == name,
                f"{name} Deployment is not bound to its exact same-named ServiceAccount")
        expected_automount = name in {"aegis-mcp-read", "aegis-mcp-action"}
        require(pod_spec.get("automountServiceAccountToken") is expected_automount,
                f"{name} ServiceAccount token automount posture differs from its role")


def validate_role_binding(binding: dict, scope: Scope, name: str) -> None:
    metadata = binding.get("metadata", {})
    require(metadata.get("name") == name and metadata.get("namespace") == scope.namespace,
            f"{name} RoleBinding identity or namespace differs from the live scope")
    require(binding.get("roleRef") == {
        "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name,
    }, f"{name} RoleBinding does not reference its exact same-named Role")
    subjects = binding.get("subjects", [])
    require(isinstance(subjects, list) and len(subjects) == 1,
            f"{name} RoleBinding must contain exactly one subject")
    subject = subjects[0]
    require(subject.get("kind") == "ServiceAccount" and subject.get("name") == name and
            subject.get("namespace") == scope.namespace and subject.get("apiGroup", "") == "",
            f"{name} RoleBinding does not target its exact same-named ServiceAccount")


def subject_includes_service_account(
        subject: dict, binding_namespace: str, namespace: str, name: str
) -> bool:
    username = f"system:serviceaccount:{namespace}:{name}"
    if subject.get("kind") == "User":
        return subject.get("name") == username
    if subject.get("kind") == "Group":
        group_name = subject.get("name")
        return group_name in {
            "system:serviceaccounts", f"system:serviceaccounts:{namespace}",
        } or (bool(binding_namespace) and group_name == "system:authenticated")
    if subject.get("kind") != "ServiceAccount" or subject.get("name") != name:
        return False
    subject_namespace = subject.get("namespace") or binding_namespace
    return subject_namespace == namespace


def validate_mcp_binding_provenance(scope: Scope) -> None:
    role_binding_list = kube_json(scope, ["get", "rolebindings"])
    cluster_role_binding_list = kube_json(scope, ["get", "clusterrolebindings"])
    role_bindings = role_binding_list.get("items")
    cluster_role_bindings = cluster_role_binding_list.get("items")
    require(isinstance(role_bindings, list) and isinstance(cluster_role_bindings, list),
            "Kubernetes RBAC binding lists were malformed")

    for name in ("aegis-mcp-read", "aegis-mcp-action"):
        matching_role_bindings = []
        for binding in role_bindings:
            binding_namespace = binding.get("metadata", {}).get("namespace", "")
            if any(subject_includes_service_account(
                    subject, binding_namespace, scope.namespace, name
            ) for subject in binding.get("subjects", [])):
                matching_role_bindings.append(binding)
        require(len(matching_role_bindings) == 1,
                f"{name} must be referenced by exactly one namespaced RoleBinding")
        validate_role_binding(matching_role_bindings[0], scope, name)

        matching_cluster_role_bindings = []
        for binding in cluster_role_bindings:
            if any(subject_includes_service_account(
                    subject, "", scope.namespace, name
            ) for subject in binding.get("subjects", [])):
                matching_cluster_role_bindings.append(binding)
        require(not matching_cluster_role_bindings,
                f"{name} must not be referenced by any ClusterRoleBinding")


def can_service_account(scope: Scope, name: str, verb: str, resource: str) -> bool:
    subject = f"system:serviceaccount:{scope.namespace}:{name}"
    answer = kubectl(
        scope, ["auth", "can-i", verb, resource, f"--as={subject}"],
    ).stdout.strip().lower()
    require(answer in {"yes", "no"},
            f"kubectl auth returned an unexpected decision for {name} {verb} {resource}")
    return answer == "yes"


def require_effective_access(
        scope: Scope, name: str, verb: str, resource: str, expected: bool
) -> None:
    allowed = can_service_account(scope, name, verb, resource)
    require(allowed is expected,
            f"{name} effective access for {verb} {resource} was "
            f"{'allowed' if allowed else 'denied'}, expected {'allowed' if expected else 'denied'}")


def validate_effective_mcp_permissions(scope: Scope) -> None:
    read_name = "aegis-mcp-read"
    action_name = "aegis-mcp-action"
    expected_allowed = {
        read_name: {
            ("get", "pods"), ("list", "pods"), ("get", "pods/log"),
            ("list", "events"), ("get", f"deployments.apps/{scope.canary}"),
            ("get", "replicasets.apps"),
        },
        action_name: {
            ("get", f"deployments.apps/{scope.canary}"),
            ("patch", f"deployments.apps/{scope.canary}"),
        },
    }
    for name, permissions in expected_allowed.items():
        for verb, resource in sorted(permissions):
            require_effective_access(scope, name, verb, resource, True)

    shared_denied: set[tuple[str, str]] = set()
    read_verbs = ("get", "list", "watch")
    mutation_verbs = ("create", "delete", "deletecollection", "patch", "update")
    for verb in read_verbs + mutation_verbs:
        shared_denied.add((verb, "secrets"))
    for subresource in ("pods/exec", "serviceaccounts/token"):
        for verb in read_verbs + mutation_verbs:
            shared_denied.add((verb, subresource))
    shared_denied.update({
        ("impersonate", "users"), ("impersonate", "groups"), ("impersonate", "serviceaccounts"),
        ("*", "*"),
    })
    for resource in (
        "configmaps", "services", "serviceaccounts", "persistentvolumeclaims",
        "statefulsets.apps", "daemonsets.apps", "jobs.batch", "cronjobs.batch",
        "ingresses.networking.k8s.io", "networkpolicies.networking.k8s.io",
        "leases.coordination.k8s.io",
        "roles.rbac.authorization.k8s.io", "rolebindings.rbac.authorization.k8s.io",
    ):
        for verb in read_verbs + mutation_verbs:
            shared_denied.add((verb, resource))
    for resource in (
        "nodes", "namespaces", "persistentvolumes", "storageclasses.storage.k8s.io",
        "clusterroles.rbac.authorization.k8s.io", "clusterrolebindings.rbac.authorization.k8s.io",
        "customresourcedefinitions.apiextensions.k8s.io",
    ):
        for verb in read_verbs + mutation_verbs:
            shared_denied.add((verb, resource))

    role_specific_denied = {
        read_name: {
            ("watch", "pods"),
            ("create", "pods"), ("delete", "pods"), ("deletecollection", "pods"),
            ("patch", "pods"), ("update", "pods"),
            ("list", "pods/log"), ("watch", "pods/log"), ("create", "pods/log"),
            ("delete", "pods/log"), ("deletecollection", "pods/log"),
            ("patch", "pods/log"), ("update", "pods/log"),
            ("get", "events"), ("watch", "events"), ("create", "events"),
            ("delete", "events"), ("deletecollection", "events"),
            ("patch", "events"), ("update", "events"),
            ("get", "deployments.apps/aegissre-e2e-denied"),
            ("list", "deployments.apps"), ("watch", "deployments.apps"),
            ("create", "deployments.apps"), ("delete", "deployments.apps"),
            ("deletecollection", "deployments.apps"),
            ("patch", f"deployments.apps/{scope.canary}"), ("update", "deployments.apps"),
            ("list", "replicasets.apps"), ("watch", "replicasets.apps"),
            ("create", "replicasets.apps"), ("delete", "replicasets.apps"),
            ("deletecollection", "replicasets.apps"),
            ("patch", "replicasets.apps"), ("update", "replicasets.apps"),
        },
        action_name: {
            ("get", "pods"), ("list", "pods"), ("watch", "pods"),
            ("create", "pods"), ("delete", "pods"), ("deletecollection", "pods"),
            ("patch", "pods"), ("update", "pods"),
            ("get", "pods/log"), ("list", "pods/log"), ("watch", "pods/log"),
            ("create", "pods/log"), ("delete", "pods/log"),
            ("deletecollection", "pods/log"), ("patch", "pods/log"),
            ("update", "pods/log"),
            ("get", "events"), ("list", "events"), ("watch", "events"),
            ("create", "events"), ("delete", "events"), ("deletecollection", "events"),
            ("patch", "events"), ("update", "events"),
            ("get", "deployments.apps/aegissre-e2e-denied"),
            ("patch", "deployments.apps/aegissre-e2e-denied"),
            ("list", "deployments.apps"), ("watch", "deployments.apps"),
            ("create", "deployments.apps"), ("delete", "deployments.apps"),
            ("deletecollection", "deployments.apps"), ("update", "deployments.apps"),
            ("get", "replicasets.apps"), ("list", "replicasets.apps"),
            ("watch", "replicasets.apps"), ("create", "replicasets.apps"),
            ("delete", "replicasets.apps"), ("deletecollection", "replicasets.apps"),
            ("patch", "replicasets.apps"),
            ("update", "replicasets.apps"),
        },
    }
    for name in (read_name, action_name):
        for verb, resource in sorted(shared_denied | role_specific_denied[name]):
            require_effective_access(scope, name, verb, resource, False)


def preflight(scope: Scope, canary_image: str) -> None:
    require(scope.context == EXPECTED_CONTEXT, f"context must be exactly {EXPECTED_CONTEXT!r}")
    require(scope.namespace == EXPECTED_NAMESPACE, f"namespace must be exactly {EXPECTED_NAMESPACE!r}")
    require(scope.canary == EXPECTED_CANARY, f"canary must be exactly {EXPECTED_CANARY!r}")
    require(bool(IMAGE_PATTERN.fullmatch(canary_image)), "--image must be pinned by sha256 digest")
    require(not canary_image.endswith("@" + ZERO_DIGEST), "--image cannot use the zero-digest sentinel")

    current = invoke(["kubectl", "config", "current-context"]).stdout.strip()
    require(current == scope.context, f"current kubectl context is {current!r}, expected {scope.context!r}")
    namespace = kube_json(scope, ["get", "namespace", scope.namespace])
    require(namespace.get("metadata", {}).get("name") == scope.namespace, "namespace identity did not match")

    deployments: dict[str, dict] = {}
    running_images: set[str] = set()
    for name in AegisDeployments:
        deployment = kube_json(scope, ["get", "deployment", name])
        deployments[name] = deployment
        running_images.add(deployment_image(deployment))
        require(deployment_available(deployment), f"{name} is not Available")
        annotations = deployment.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
        require(annotations.get("aegissre.io/release-profile") == "laboratory-execute",
                f"{name} was not rendered from the laboratory execute profile")
    require(len(running_images) == 1, "AegisSRE Deployments do not run one identical immutable image")
    validate_runtime_service_accounts(deployments)
    validate_mcp_binding_provenance(scope)
    validate_runtime_transport(scope, deployments)
    validate_runtime_delegation(deployments)
    validate_runtime_database(deployments)
    validate_runtime_workload_policy(scope, deployments)
    validate_runtime_network(scope, deployments)

    monitor = deployments["aegis-monitor"]
    env_from = (
        monitor.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])[0].get("envFrom", [])
    )
    config_names = [entry.get("configMapRef", {}).get("name", "") for entry in env_from]
    config_names = [name for name in config_names if name]
    require(len(config_names) == 1, "Monitor must reference exactly one generated configuration ConfigMap")
    config = kube_json(scope, ["get", "configmap", config_names[0]]).get("data", {})
    require(config.get("AEGIS_DRY_RUN") == "false", "live acceptance requires AEGIS_DRY_RUN=false")
    require(config.get("AEGIS_ALLOW_MUTATIONS") == "true", "live acceptance requires AEGIS_ALLOW_MUTATIONS=true")
    require(config.get("AEGIS_ALLOW_LOG_TRACE_ACTIONS") == "false",
            "live acceptance requires log/trace-triggered writes to remain disabled")
    require(config.get("AEGIS_WHATSAPP_ENABLED") == "false",
            "live acceptance will not send a real WhatsApp notification")
    require(config.get("AEGIS_MTLS_ENABLED") == "true",
            "live acceptance requires mTLS for all application traffic")
    require(config.get("AEGIS_LISTEN_ADDR") == ":8443" and
            config.get("AEGIS_ADMIN_LISTEN_ADDR") == ":9090",
            "application and health listeners are not separated")
    require(config.get("AEGIS_OBSERVE_MCP_URL") == "https://aegis-mcp-read:8443/mcp" and
            config.get("AEGIS_OPERATE_MCP_URL") == "https://aegis-mcp-action:8443/mcp" and
            config.get("AEGIS_INVESTIGATOR_URL") == "https://aegis-investigator:8443" and
            config.get("AEGIS_OPERATOR_URL") == "https://aegis-operator:8443",
            "live acceptance found a plaintext or unexpected internal endpoint")
    require(config.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") ==
            "http://otel-collector.observability.svc.cluster.local:4318/v1/traces",
            "live acceptance requires OTLP traces through the in-cluster collector")

    for role_name in ("aegis-mcp-read", "aegis-mcp-action"):
        role = kube_json(scope, ["get", "role", role_name])
        validate_mcp_role(role, scope, role_name)

    validate_effective_mcp_permissions(scope)

    existing = kubectl(scope, ["get", "deployment", scope.canary], check=False)
    require(existing.returncode != 0, "canary already exists; refusing to adopt or overwrite it")


def render_canary(scope: Scope, image: str, run_id: str) -> str:
    template_path = pathlib.Path(__file__).resolve().parent / "k3s" / "canary.yaml"
    rendered = template_path.read_text(encoding="utf-8")
    replacements = {
        "__CANARY_NAME__": scope.canary,
        "__NAMESPACE__": scope.namespace,
        "__CANARY_IMAGE__": image,
        "__RUN_ID__": run_id,
    }
    for old, new in replacements.items():
        rendered = rendered.replace(old, new)
    require("__" not in rendered, "canary template contains an unresolved placeholder")
    return rendered


def wait_for_initial_failure(scope: Scope, run_id: str, timeout_seconds: int) -> int:
    deadline = time.monotonic() + min(timeout_seconds, 180)
    while time.monotonic() < deadline:
        deployment = kube_json(scope, ["get", "deployment", scope.canary])
        require(owned_by_run(deployment, run_id),
                "canary ownership or run marker changed before initial failure verification")
        metadata = deployment.get("metadata", {})
        annotations = deployment.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
        status = deployment.get("status", {})
        if not annotations.get("aegissre.io/grant-id") and status.get("unavailableReplicas", 0) >= 1:
            return int(metadata.get("generation", 0))
        time.sleep(2)
    raise AcceptanceError("canary did not reach the intentional unavailable state")


def wait_for_recovery(scope: Scope, run_id: str, initial_generation: int, timeout_seconds: int) -> tuple[str, int]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        deployment = kube_json(scope, ["get", "deployment", scope.canary])
        require(owned_by_run(deployment, run_id),
                "canary ownership or run marker changed during recovery verification")
        metadata = deployment.get("metadata", {})
        template = deployment.get("spec", {}).get("template", {}).get("metadata", {})
        grant_id = template.get("annotations", {}).get("aegissre.io/grant-id", "")
        if grant_id and deployment_available(deployment):
            generation = int(metadata.get("generation", 0))
            require(generation == initial_generation + 1,
                    f"expected exactly one canary template mutation; generation moved {initial_generation} -> {generation}")
            return grant_id, generation
        time.sleep(5)
    raise AcceptanceError("AegisSRE did not mutate and recover the canary before the timeout")


def correlated_terminal_report(logs: str, scope: Scope, grant_id: str) -> str | None:
    """Return the sole incident proven by exact target/grant resolved and report events."""
    resolved: set[str] = set()
    reported: set[str] = set()
    for line in logs.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        incident_id = event.get("incident_id")
        exact_target = (
            event.get("target_api_version") == "apps/v1"
            and event.get("target_kind") == "Deployment"
            and event.get("target_namespace") == scope.namespace
            and event.get("target_name") == scope.canary
        )
        if not isinstance(incident_id, str) or not incident_id or not exact_target:
            continue
        if event.get("grant_id") != grant_id:
            continue
        if event.get("msg") == "incident outcome" and event.get("status") == "resolved":
            resolved.add(incident_id)
        if event.get("msg") == "incident report outcome" and isinstance(event.get("report_id"), str) \
                and event.get("report_id"):
            reported.add(incident_id)

    matches = resolved & reported
    if len(matches) > 1:
        raise AcceptanceError("one recovered grant was correlated to multiple terminal incidents")
    return next(iter(matches)) if matches else None


def terminal_report_seen(
        scope: Scope, since_time: str, grant_id: str, timeout_seconds: int = 120
) -> str | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed = kubectl(
            scope,
            ["logs", "deployment/aegis-monitor", f"--since-time={since_time}"],
            check=False,
        )
        if completed.returncode == 0:
            incident_id = correlated_terminal_report(completed.stdout, scope, grant_id)
            if incident_id is not None:
                return incident_id
        time.sleep(5)
    return None


def owned_by_run(deployment: dict, run_id: str) -> bool:
    metadata = deployment.get("metadata", {})
    template_metadata = deployment.get("spec", {}).get("template", {}).get("metadata", {})
    return (
        metadata.get("labels", {}).get("app.kubernetes.io/managed-by") == "aegissre-e2e"
        and metadata.get("annotations", {}).get("aegissre.io/e2e-run") == run_id
        and template_metadata.get("labels", {}).get("app.kubernetes.io/managed-by") == "aegissre-e2e"
        and template_metadata.get("annotations", {}).get("aegissre.io/e2e-run") == run_id
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, help=f"must be {EXPECTED_CONTEXT}")
    parser.add_argument("--namespace", required=True, help=f"must be {EXPECTED_NAMESPACE}")
    parser.add_argument("--canary", required=True, help=f"must be {EXPECTED_CANARY}")
    parser.add_argument("--ack", required=True, help=f"must equal {ACKNOWLEDGEMENT}")
    parser.add_argument("--image", required=True, help="approved shell-capable canary image pinned by sha256 digest")
    parser.add_argument("--run-id", help="optional DNS-label-safe run ID; generated when omitted")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--execute", action="store_true", help="create the canary and run the live mutation exercise")
    args = parser.parse_args()

    scope = Scope(args.context, args.namespace, args.canary)
    try:
        require(args.ack == ACKNOWLEDGEMENT, "explicit mutation acknowledgement did not match")
        require(60 <= args.timeout_seconds <= 1800, "timeout must be between 60 and 1800 seconds")
        run_id = args.run_id or "run-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        require(bool(RUN_ID_PATTERN.fullmatch(run_id)), "run ID must be a DNS-label-safe value up to 63 characters")
        preflight(scope, args.image)

        print(f"preflight passed: context={scope.context} namespace={scope.namespace} canary={scope.canary}")
        if not args.execute:
            print(
                "plan only: no resources were created or changed; Secret objects and bytes were not read. "
                "Secret assurance is limited to Deployment projection metadata and workload readiness. "
                "Pass --execute to prove the "
                "mTLS, delegation, PostgreSQL, remediation, and reporting workflow"
            )
            return 0

        started_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        manifest = render_canary(scope, args.image, run_id)
        kubectl(
            scope,
            ["create", "-f", "-"],
            stdin=manifest,
        )
        initial_generation = wait_for_initial_failure(scope, run_id, args.timeout_seconds)
        grant_id, final_generation = wait_for_recovery(
            scope, run_id, initial_generation, args.timeout_seconds
        )
        incident_id = terminal_report_seen(scope, started_at, grant_id)
        require(incident_id is not None,
                "canary recovered but Monitor did not emit a matching resolved terminal-report outcome")
        final_deployment = kube_json(scope, ["get", "deployment", scope.canary])
        final_template_annotations = final_deployment.get("spec", {}).get("template", {}).get(
            "metadata", {}
        ).get("annotations", {})
        require(owned_by_run(final_deployment, run_id),
                "canary ownership or run marker changed before terminal acceptance")
        require(final_template_annotations.get("aegissre.io/grant-id") == grant_id,
                "canary grant marker changed before terminal acceptance")
        require(int(final_deployment.get("metadata", {}).get("generation", 0)) == final_generation,
                "canary changed again after the verified delegated restart")
        print(
            "acceptance passed: one delegated restart recovered the canary and produced a terminal report "
            f"(generation {initial_generation}->{final_generation}, grant={grant_id}, incident={incident_id})"
        )

        print(
            "canary retained for evidence; remove it through reviewed GitOps or a Kubernetes API DELETE "
            "that is preconditioned on the captured object UID, never from labels or annotations alone"
        )
        return 0
    except (AcceptanceError, OSError) as error:
        print(f"k3s acceptance failed: {error}", file=sys.stderr)
        print("the script does not clean up failed runs automatically so evidence is preserved", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
