// Verifies AegisSRE-signed AgentFacts with the NANDA Index's own signing code
// (nanda-index-v2 server/src/services/signing.ts, copied beside this file).
// usage: node --experimental-strip-types verify.ts <dir with facts.json and public.pem>
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, verifyCanonical } from "./signing.ts";

const dir = process.argv[2];
const raw = readFileSync(join(dir, "facts.json"), "utf8");
const pem = readFileSync(join(dir, "public.pem"), "utf8");
const record = JSON.parse(raw);

const checks: Array<[string, boolean]> = [
  ["NANDA verifyCanonical accepts the AegisSRE signature", verifyCanonical(record, record.signature_value, pem, "ed25519")],
  ["Go canonical bytes equal NANDA canonicalize()", raw === canonicalize(record)],
  ["NANDA rejects a tampered copy", !verifyCanonical({ ...record, label: "Impostor" }, record.signature_value, pem, "ed25519")],
];
let failed = false;
for (const [name, ok] of checks) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  failed ||= !ok;
}
process.exit(failed ? 1 : 0);
