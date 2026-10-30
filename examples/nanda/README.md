# NANDA discovery against a self-hosted NANDA Index

This runs the five-process fixture topology with Monitor finding Investigator and Operator only through a real [nanda-index-v2](https://github.com/projnanda/nanda-index-v2). It needs Docker, Go and `curl`.

## 1. Start a NANDA Index

```bash
git clone https://github.com/projnanda/nanda-index-v2.git && cd nanda-index-v2
cp .env.example .env            # SMTP_URL=log prints verification links to the log
docker compose -p nanda up -d --build db server
curl -s localhost:3001/health   # {"status":"ok","db":"ok"}
```

## 2. Register the two agents

Create and verify an account, then one entry per agent. The Index allows one verified entry per domain, so each agent gets its own subdomain.

```bash
A=http://localhost:3001
curl -s -X POST $A/auth/register -H 'content-type: application/json' \
  -d '{"email":"you@example.org","password":"<password>"}'
# open the verify-account link from `docker logs nanda-server-1`, or POST its token:
curl -s -X POST $A/auth/verify-account -H 'content-type: application/json' -d '{"token":"<token>"}'
JWT=$(curl -s -X POST $A/auth/login -H 'content-type: application/json' \
  -d '{"email":"you@example.org","password":"<password>"}' | jq -r .token)

for n in investigator operator; do
  curl -s -X POST $A/api/v1/orgs -H "authorization: Bearer $JWT" -H 'content-type: application/json' -d '{
    "org_id": "aegissre-'$n'", "display_name": "AegisSRE '$n'", "contact_email": "you@example.org",
    "hosting_path": "smb", "domain": "'$n'.aegissre.test",
    "identifier": "urn:air:'$n'.aegissre.test:agent:'$n'",
    "media_type": "application/a2a-agent-card+json",
    "registry_url": "http://'$n'.aegissre.test:8080/.well-known/agent-card.json"}'
done
```

The entries stay unresolvable until their domains are proven. `.test` domains have no DNS, so for this local run use the test activation from the nanda-index-v2 README:

```bash
docker compose -p nanda exec -T db psql -U nanda -d nanda_index -c \
  "UPDATE organizations SET status='active', email_verified=true, domain_verified=true
   WHERE org_id IN ('aegissre-investigator','aegissre-operator');"
```

On a real domain, request `POST /api/v1/orgs/<org_id>/domain-challenge`, publish the TXT record and call `verify-domain` instead.

## 3. Run AegisSRE with NANDA discovery

From the AegisSRE repository, generate keys into `examples/nanda/.env` (git-ignored):

```bash
inv=$(go run ./cmd/aegissre keygen -agentfacts); op=$(go run ./cmd/aegissre keygen -agentfacts)
{
  echo "NANDA_INVESTIGATOR_PRIVATE_KEY=$(sed -n 's/^AEGIS_AGENTFACTS_PRIVATE_KEY=//p' <<<"$inv")"
  echo "NANDA_INVESTIGATOR_DID=$(sed -n 's/^AGENTFACTS_DID_KEY=//p' <<<"$inv")"
  echo "NANDA_OPERATOR_PRIVATE_KEY=$(sed -n 's/^AEGIS_AGENTFACTS_PRIVATE_KEY=//p' <<<"$op")"
  echo "NANDA_OPERATOR_DID=$(sed -n 's/^AGENTFACTS_DID_KEY=//p' <<<"$op")"
  go run ./cmd/aegissre keygen | grep -E '^AEGIS_DELEGATION_(PRIVATE|PUBLIC)_KEY='
} > examples/nanda/.env

docker build --build-arg GO_VERSION=1.26.10 --tag aegissre:local .
docker compose -f compose.yaml -f examples/nanda/compose.yaml --env-file examples/nanda/.env up -d --no-build --wait
docker compose -f compose.yaml -f examples/nanda/compose.yaml --env-file examples/nanda/.env logs -f aegis-monitor
```

Monitor's static peer addresses are set to `http://static.invalid`, so every incident that reaches a diagnosis and a dry-run receipt went through the Index. `curl localhost:8082/agentfacts.json` shows the Investigator's signed AgentFacts.

To see an impostor refused, pin the wrong key and recreate Monitor:

```bash
NANDA_OPERATOR_DID=$(grep NANDA_INVESTIGATOR_DID examples/nanda/.env | cut -d= -f2) \
  docker compose -f compose.yaml -f examples/nanda/compose.yaml --env-file examples/nanda/.env \
  up -d --no-build --force-recreate aegis-monitor
# incident outcome: escalated … AgentFacts is signed by a key other than the pinned key
```
