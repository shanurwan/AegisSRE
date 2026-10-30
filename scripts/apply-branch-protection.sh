#!/usr/bin/env bash
# Create or update the `main` ruleset from .github/rulesets/main.json, so the
# protection on the default branch is reviewed like any other change.
# Needs gh authenticated as a repository admin, and a public repository or a
# plan that includes rulesets for private repositories.
#
# usage: scripts/apply-branch-protection.sh [owner/repo]
set -euo pipefail

repo="${1:-shanurwan/AegisSRE}"
ruleset=.github/rulesets/main.json
name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$ruleset")"

id="$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id")"
if [[ -n "$id" ]]; then
  gh api --method PUT "repos/$repo/rulesets/$id" --input "$ruleset" --jq '"updated ruleset \(.id): \(.name)"'
else
  gh api --method POST "repos/$repo/rulesets" --input "$ruleset" --jq '"created ruleset \(.id): \(.name)"'
fi
