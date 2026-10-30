import json
import pathlib
import tempfile
import unittest

import gate


def report(*alerts):
    return {"site": [{"alerts": list(alerts)}]}


def alert(plugin, risk, method, uri):
    return {
        "pluginid": plugin,
        "alert": "test alert",
        "riskcode": str(risk),
        "riskdesc": "test",
        "instances": [{"method": method, "uri": uri, "evidence": ""}],
    }


class GateTest(unittest.TestCase):
    def run_gate(self, document):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "report.json")
            path.write_text(json.dumps(document), encoding="utf-8")
            return gate.main([str(path)])

    def test_accepts_the_exact_reviewed_exception(self):
        self.assertEqual(0, self.run_gate(report(
            alert("10098", 2, "GET", "http://aegis-monitor:8080/.well-known/agent-card.json"),
        )))

    def test_same_rule_on_another_path_still_fails(self):
        self.assertEqual(1, self.run_gate(report(
            alert("10098", 2, "GET", "http://aegis-monitor:8080/.well-known/agent-card.json"),
            alert("10098", 2, "POST", "http://aegis-monitor:8080/a2a"),
        )))

    def test_same_path_with_another_method_still_fails(self):
        self.assertEqual(1, self.run_gate(report(
            alert("10098", 2, "POST", "http://aegis-monitor:8080/.well-known/agent-card.json"),
        )))

    def test_low_risk_fails_and_informational_does_not(self):
        self.assertEqual(1, self.run_gate(report(alert("10021", 1, "GET", "http://x:8080/healthz"))))
        self.assertEqual(0, self.run_gate(report(alert("10049", 0, "GET", "http://x:8080/healthz"))))


if __name__ == "__main__":
    unittest.main()
