import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("e2e-k3s.py")
SPEC = importlib.util.spec_from_file_location("aegissre_e2e_k3s", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load live acceptance harness")
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class TerminalReportCorrelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = HARNESS.Scope("laboratory", "outage-arena", "aegissre-e2e-canary")

    def event(self, message: str, incident: str, grant: str, **extra: str) -> dict:
        event = {
            "msg": message,
            "incident_id": incident,
            "grant_id": grant,
            "target_api_version": "apps/v1",
            "target_kind": "Deployment",
            "target_namespace": self.scope.namespace,
            "target_name": self.scope.canary,
        }
        event.update(extra)
        return event

    @staticmethod
    def logs(*events: dict) -> str:
        return "\n".join(json.dumps(event) for event in events)

    def test_requires_same_incident_grant_and_exact_canary(self) -> None:
        logs = self.logs(
            self.event("incident outcome", "incident-stale", "grant-stale", status="resolved"),
            self.event("incident report outcome", "incident-stale", "grant-stale", report_id="report-stale"),
            self.event("incident outcome", "incident-live", "grant-live", status="resolved"),
            self.event("incident report outcome", "incident-live", "grant-live", report_id="report-live"),
        )
        self.assertEqual(
            HARNESS.correlated_terminal_report(logs, self.scope, "grant-live"),
            "incident-live",
        )

    def test_rejects_partial_or_cross_incident_matches(self) -> None:
        wrong_target = self.event(
            "incident report outcome", "incident-live", "grant-live", report_id="report-live"
        )
        wrong_target["target_name"] = "unrelated-deployment"
        logs = self.logs(
            self.event("incident outcome", "incident-live", "grant-live", status="resolved"),
            self.event("incident report outcome", "incident-other", "grant-live", report_id="report-other"),
            self.event("incident report outcome", "incident-live", "grant-other", report_id="report-live"),
            wrong_target,
            {"msg": "not-json-correlation", "incident_id": "incident-live"},
        )
        self.assertIsNone(HARNESS.correlated_terminal_report(logs, self.scope, "grant-live"))

    def test_rejects_one_grant_correlated_to_multiple_incidents(self) -> None:
        logs = self.logs(
            self.event("incident outcome", "incident-one", "grant-live", status="resolved"),
            self.event("incident report outcome", "incident-one", "grant-live", report_id="report-one"),
            self.event("incident outcome", "incident-two", "grant-live", status="resolved"),
            self.event("incident report outcome", "incident-two", "grant-live", report_id="report-two"),
        )
        with self.assertRaises(HARNESS.AcceptanceError):
            HARNESS.correlated_terminal_report(logs, self.scope, "grant-live")

    def test_run_ownership_requires_deployment_and_pod_template_markers(self) -> None:
        deployment = {
            "metadata": {
                "labels": {"app.kubernetes.io/managed-by": "aegissre-e2e"},
                "annotations": {"aegissre.io/e2e-run": "run-live"},
            },
            "spec": {"template": {"metadata": {
                "labels": {"app.kubernetes.io/managed-by": "aegissre-e2e"},
                "annotations": {"aegissre.io/e2e-run": "run-live"},
            }}},
        }
        self.assertTrue(HARNESS.owned_by_run(deployment, "run-live"))
        deployment["spec"]["template"]["metadata"]["annotations"]["aegissre.io/e2e-run"] = "run-other"
        self.assertFalse(HARNESS.owned_by_run(deployment, "run-live"))


class NetworkPolicyInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = HARNESS.Scope("laboratory", "outage-arena", "aegissre-e2e-canary")
        self.deployments = {
            name: {"spec": {"template": {"metadata": {"labels": {
                "app.kubernetes.io/name": name,
                "app.kubernetes.io/part-of": "aegissre",
            }}}}}
            for name in HARNESS.AegisDeployments
        }

    def policy(self, name: str, selector: dict) -> dict:
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": self.scope.namespace},
            "spec": {"podSelector": selector},
        }

    def load(self, policies: list[dict]) -> dict[str, dict]:
        listing = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicyList",
            "items": policies,
        }
        with mock.patch.object(HARNESS, "kube_json", return_value=listing) as kube_json:
            result = HARNESS.load_runtime_network_policies(
                self.scope, self.deployments, {"expected-policy"}
            )
        kube_json.assert_called_once_with(self.scope, ["get", "networkpolicies"])
        return result

    def test_allows_unrelated_additive_policy(self) -> None:
        policies = self.load([
            self.policy("expected-policy", {
                "matchLabels": {"app.kubernetes.io/name": "aegis-monitor"},
            }),
            self.policy("unrelated-policy", {"matchLabels": {"team": "payments"}}),
        ])
        self.assertEqual(set(policies), {"expected-policy", "unrelated-policy"})

    def test_rejects_unexpected_selectors_that_match_an_aegis_pod(self) -> None:
        selectors = {
            "empty": {},
            "in": {"matchExpressions": [{
                "key": "app.kubernetes.io/name", "operator": "In", "values": ["aegis-monitor"],
            }]},
            "not-in": {"matchExpressions": [{
                "key": "app.kubernetes.io/name", "operator": "NotIn", "values": ["other"],
            }]},
            "exists": {"matchExpressions": [{
                "key": "app.kubernetes.io/part-of", "operator": "Exists",
            }]},
            "does-not-exist": {"matchExpressions": [{
                "key": "unassigned.example.com/tier", "operator": "DoesNotExist",
            }]},
        }
        expected = self.policy("expected-policy", {
            "matchLabels": {"app.kubernetes.io/name": "aegis-monitor"},
        })
        for name, selector in selectors.items():
            with self.subTest(selector=name):
                with self.assertRaises(HARNESS.AcceptanceError):
                    self.load([expected, self.policy("unexpected-policy", selector)])

    def test_rejects_malformed_namespace_or_duplicate_policy_list(self) -> None:
        expected = self.policy("expected-policy", {
            "matchLabels": {"app.kubernetes.io/name": "aegis-monitor"},
        })
        wrong_namespace = copy.deepcopy(expected)
        wrong_namespace["metadata"]["namespace"] = "other"
        cases = {
            "wrong namespace": [wrong_namespace],
            "duplicate": [expected, copy.deepcopy(expected)],
        }
        for name, policies in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(HARNESS.AcceptanceError):
                    self.load(policies)

        malformed_listing = {"apiVersion": "v1", "kind": "List", "items": []}
        with mock.patch.object(HARNESS, "kube_json", return_value=malformed_listing):
            with self.assertRaises(HARNESS.AcceptanceError):
                HARNESS.load_runtime_network_policies(
                    self.scope, self.deployments, {"expected-policy"}
                )

    def test_policy_direction_and_kubernetes_api_egress_are_exact(self) -> None:
        spec = {
            "podSelector": {"matchExpressions": [{
                "key": "app.kubernetes.io/name", "operator": "In",
                "values": ["aegis-mcp-read", "aegis-mcp-action"],
            }]},
            "policyTypes": ["Egress"],
            "egress": [{
                "ports": [{"port": 443, "protocol": "TCP"}],
                "to": [{"ipBlock": {"cidr": "10.43.0.1/32"}}],
            }],
        }
        HARNESS.validate_kubernetes_api_egress(spec)
        for name, mutate in {
            "opposite direction": lambda value: value.update({"ingress": []}),
            "wrong policy types": lambda value: value.update({"policyTypes": ["Ingress", "Egress"]}),
            "broad API CIDR": lambda value: value["egress"][0]["to"][0]["ipBlock"].update({
                "cidr": "10.43.0.0/16",
            }),
        }.items():
            changed = copy.deepcopy(spec)
            mutate(changed)
            with self.subTest(case=name):
                with self.assertRaises(HARNESS.AcceptanceError):
                    HARNESS.validate_kubernetes_api_egress(changed)


class PreflightAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = HARNESS.Scope("laboratory", "outage-arena", "aegissre-e2e-canary")

    def test_every_deployment_uses_its_exact_service_account(self) -> None:
        deployments = {
            name: {"spec": {"template": {"spec": {
                "serviceAccountName": name,
                "automountServiceAccountToken": name in {"aegis-mcp-read", "aegis-mcp-action"},
            }}}}
            for name in HARNESS.AegisDeployments
        }
        HARNESS.validate_runtime_service_accounts(deployments)
        deployments["aegis-operator"]["spec"]["template"]["spec"]["serviceAccountName"] = "default"
        with self.assertRaises(HARNESS.AcceptanceError):
            HARNESS.validate_runtime_service_accounts(deployments)

    def test_role_binding_requires_one_same_named_role_and_service_account(self) -> None:
        binding = {
            "metadata": {"name": "aegis-mcp-read", "namespace": self.scope.namespace},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "aegis-mcp-read",
            },
            "subjects": [{
                "kind": "ServiceAccount", "name": "aegis-mcp-read", "namespace": self.scope.namespace,
            }],
        }
        HARNESS.validate_role_binding(binding, self.scope, "aegis-mcp-read")
        binding["subjects"].append({
            "kind": "ServiceAccount", "name": "default", "namespace": self.scope.namespace,
        })
        with self.assertRaises(HARNESS.AcceptanceError):
            HARNESS.validate_role_binding(binding, self.scope, "aegis-mcp-read")

    def test_action_role_is_normalized_to_exact_apps_canary_get_patch(self) -> None:
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "aegis-mcp-action", "namespace": self.scope.namespace},
            "rules": [{
                "apiGroups": ["apps"], "resources": ["deployments"],
                "resourceNames": [self.scope.canary], "verbs": ["patch", "get"],
            }],
        }
        HARNESS.validate_mcp_role(role, self.scope, "aegis-mcp-action")
        for name, mutate in {
            "core api group": lambda value: value["rules"][0].update({"apiGroups": [""]}),
            "broader target": lambda value: value["rules"][0].update({"resourceNames": []}),
            "extra verb": lambda value: value["rules"][0].update({"verbs": ["get", "patch", "update"]}),
            "duplicate rule": lambda value: value["rules"].append(copy.deepcopy(value["rules"][0])),
        }.items():
            changed = copy.deepcopy(role)
            mutate(changed)
            with self.subTest(case=name):
                with self.assertRaises(HARNESS.AcceptanceError):
                    HARNESS.validate_mcp_role(changed, self.scope, "aegis-mcp-action")

    def test_binding_provenance_rejects_extra_namespaced_or_cluster_binding(self) -> None:
        def expected_binding(name: str) -> dict:
            return {
                "metadata": {"name": name, "namespace": self.scope.namespace},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name,
                },
                "subjects": [{
                    "kind": "ServiceAccount", "name": name, "namespace": self.scope.namespace,
                }],
            }

        expected = [expected_binding("aegis-mcp-read"), expected_binding("aegis-mcp-action")]

        def validate(role_bindings: list[dict], cluster_role_bindings: list[dict]) -> None:
            def fake_kube_json(_scope, arguments):
                if arguments == ["get", "rolebindings"]:
                    return {"items": role_bindings}
                if arguments == ["get", "clusterrolebindings"]:
                    return {"items": cluster_role_bindings}
                raise AssertionError(arguments)

            with mock.patch.object(HARNESS, "kube_json", side_effect=fake_kube_json):
                HARNESS.validate_mcp_binding_provenance(self.scope)

        validate(expected, [])
        extra_role_binding = {
            "metadata": {"name": "unexpected", "namespace": self.scope.namespace},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "edit",
            },
            "subjects": [{
                "kind": "Group", "name": f"system:serviceaccounts:{self.scope.namespace}",
            }],
        }
        with self.assertRaises(HARNESS.AcceptanceError):
            validate([*expected, extra_role_binding], [])

        extra_cluster_role_binding = {
            "metadata": {"name": "unexpected-cluster"},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view",
            },
            "subjects": [{
                "kind": "ServiceAccount", "name": "aegis-mcp-action", "namespace": self.scope.namespace,
            }],
        }
        with self.assertRaises(HARNESS.AcceptanceError):
            validate(expected, [extra_cluster_role_binding])

    def test_effective_permissions_check_real_subjects_and_sensitive_denials(self) -> None:
        expected_allowed = {
            "aegis-mcp-read": {
                ("get", "pods"), ("list", "pods"), ("get", "pods/log"),
                ("list", "events"), ("get", "deployments.apps/aegissre-e2e-canary"),
                ("get", "replicasets.apps"),
            },
            "aegis-mcp-action": {
                ("get", "deployments.apps/aegissre-e2e-canary"),
                ("patch", "deployments.apps/aegissre-e2e-canary"),
            },
        }
        observed: set[tuple[str, str, str]] = set()

        def fake_kubectl(scope, arguments, **_kwargs):
            self.assertEqual(scope, self.scope)
            self.assertEqual(arguments[:2], ["auth", "can-i"])
            name = arguments[4].rsplit(":", 1)[-1]
            verb, resource = arguments[2], arguments[3]
            observed.add((name, verb, resource))
            answer = "yes" if (verb, resource) in expected_allowed[name] else "no"
            return subprocess.CompletedProcess(arguments, 0, stdout=answer + "\n", stderr="")

        with mock.patch.object(HARNESS, "kubectl", side_effect=fake_kubectl):
            HARNESS.validate_effective_mcp_permissions(self.scope)

        for name in expected_allowed:
            self.assertIn((name, "get", "secrets"), observed)
            self.assertIn((name, "create", "pods/exec"), observed)
            self.assertIn((name, "create", "serviceaccounts/token"), observed)
            self.assertIn((name, "*", "*"), observed)

    def test_effective_permissions_fail_on_permission_added_elsewhere(self) -> None:
        def overprivileged(_scope, arguments, **_kwargs):
            name = arguments[4].rsplit(":", 1)[-1]
            verb, resource = arguments[2], arguments[3]
            allowed = (
                name == "aegis-mcp-read" and (verb, resource) in {
                    ("get", "pods"), ("list", "pods"), ("get", "pods/log"),
                    ("list", "events"), ("get", "deployments.apps/aegissre-e2e-canary"),
                    ("get", "replicasets.apps"), ("get", "secrets"),
                }
            ) or (
                name == "aegis-mcp-action" and (verb, resource) in {
                    ("get", "deployments.apps/aegissre-e2e-canary"),
                    ("patch", "deployments.apps/aegissre-e2e-canary"),
                }
            )
            return subprocess.CompletedProcess(
                arguments, 0, stdout=("yes\n" if allowed else "no\n"), stderr=""
            )

        with mock.patch.object(HARNESS, "kubectl", side_effect=overprivileged):
            with self.assertRaises(HARNESS.AcceptanceError):
                HARNESS.validate_effective_mcp_permissions(self.scope)

    def test_harness_has_no_automatic_delete_path(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("--cleanup", source)
        self.assertNotIn('["delete", "deployment"', source)
        self.assertNotIn('["apply", "--server-side"', source)
        self.assertIn('["create", "-f", "-"]', source)
        self.assertNotIn('help="apply the canary', source)
        self.assertIn('help="create the canary', source)


if __name__ == "__main__":
    unittest.main()
