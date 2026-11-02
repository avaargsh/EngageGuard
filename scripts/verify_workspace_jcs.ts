// TypeScript/Node independent verifier for the fixed all-string WorkspaceWrite
// v0.1 JCS subset. This does NOT implement generic ActionRequest RFC8785.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

type WorkspaceAction = Record<string, string>;
type Vector = { name: string; action: WorkspaceAction; canonical: string; sha256: string };
type Fixtures = { schema_version: string; domain_separator: string; vectors: Vector[] };

const fields = [
  "agent_id", "audience", "capability_id", "content_digest",
  "operation_id", "policy_version", "relative_path", "schema_version",
  "subject_id", "tenant_id", "tool_binding_digest", "workspace_id",
];
const fixture = JSON.parse(readFileSync(new URL("../testdata/workspace-actionhash-v01.json", import.meta.url), "utf8")) as Fixtures;

function check(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}
check(fixture.schema_version === "workspace-actionhash-fixtures.v0.1", "wrong schema");
check(fixture.domain_separator === String.raw`engageguard/action-hash/v1\u0000`, "wrong domain");
check(fixture.vectors.length === 4, "wrong number of fixtures");

for (const v of fixture.vectors) {
  const keys = Object.keys(v.action).sort();
  check(keys.length === fields.length && keys.every((key, i) => key === fields[i]), "unexpected keys: " + v.name);
  check(Object.values(v.action).every((value) => typeof value === "string"), "non-string value: " + v.name);
  // These fixed ASCII property names have identical UTF-16 and ASCII sort order.
  const canonical = JSON.stringify(Object.fromEntries(keys.map((key) => [key, v.action[key]])));
  check(canonical === v.canonical, "canonical mismatch: " + v.name);
  const sha256 = createHash("sha256")
    .update("engageguard/action-hash/v1\0", "utf8")
    .update(canonical, "utf8")
    .digest("hex");
  check(sha256 === v.sha256, "digest mismatch: " + v.name);
  console.log("typescript WorkspaceWrite JCS-subset OK: " + v.name);
}
