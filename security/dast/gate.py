"""Fail a DAST run on any ZAP alert of Low risk or above that is not an
exactly matching, reviewed entry in accepted-risks.json.

Exceptions are scoped to one rule, one method and one path, so accepting a
public document's CORS policy can never hide the same rule firing elsewhere.

usage: python3 security/dast/gate.py <report.json>...
"""

from __future__ import annotations

import json
import pathlib
import sys
from urllib.parse import urlsplit

ACCEPTED = pathlib.Path(__file__).with_name("accepted-risks.json")


def main(paths: list[str]) -> int:
    accepted = {
        (entry["plugin"], entry["method"], entry["path"])
        for entry in json.loads(ACCEPTED.read_text(encoding="utf-8"))
    }
    used: set[tuple[str, str, str]] = set()
    violations: list[str] = []
    for path in paths:
        report = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                if int(alert["riskcode"]) < 1:
                    continue
                for instance in alert.get("instances", []):
                    key = (alert["pluginid"], instance["method"], urlsplit(instance["uri"]).path)
                    if key in accepted:
                        used.add(key)
                        continue
                    violations.append(
                        f"{path}: [{alert['pluginid']}] {alert['alert']} ({alert['riskdesc']}) "
                        f"{instance['method']} {instance['uri']} evidence={instance.get('evidence', '')!r}"
                    )
    for key in sorted(accepted - used):
        print(f"note: accepted risk no longer observed, consider removing it: {key}")
    for violation in violations:
        print(violation)
    print(f"DAST gate: {len(violations)} unaccepted alert instance(s) across {len(paths)} report(s)")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
