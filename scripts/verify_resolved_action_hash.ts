import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

type JSONValue = null | boolean | number | string | JSONValue[] | { [key: string]: JSONValue };

const root = resolve(import.meta.dirname ?? process.cwd());
const domain = "engageguard/action-hash/v1\0";

function assertWellFormedUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error("unpaired high surrogate in JSON string");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("unpaired low surrogate in JSON string");
    }
  }
}

function canonicalize(value: JSONValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    assertWellFormedUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number is not valid JCS");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalize(item)).join(",") + "]";
  }
  const keys = Object.keys(value).sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  return "{" + keys.map((key) => {
    assertWellFormedUnicode(key);
    return JSON.stringify(key) + ":" + canonicalize(value[key]);
  }).join(",") + "}";
}

function readJSON<T>(relativePath: string): T {
  return JSON.parse(readFileSync(resolve(root, relativePath), "utf8")) as T;
}

function verifyNumberVectors(): number {
  const fixture = readJSON<{
    schema_version: string;
    vectors: Array<{ input: string; canonical: string }>;
  }>("docs/contracts/jcs-number-vectors.v1.json");
  if (fixture.schema_version !== "jcs-number-vectors.v1") throw new Error("unexpected numeric vector version");
  for (const vector of fixture.vectors) {
    const actual = JSON.stringify({ n: Number(vector.input) });
    const expected = JSON.stringify({ n: Number(vector.canonical) });
    if (actual !== expected) throw new Error(`number vector ${vector.input}: got ${actual}, want ${expected}`);
    if (actual !== `{"n":${vector.canonical}}`) {
      throw new Error(`number vector ${vector.input} has non-ECMAScript canonical form ${actual}`);
    }
  }
  return fixture.vectors.length;
}

function verifyResolvedActionHash(): string {
  const fixture = readJSON<{
    schema_version: string;
    action_hash: {
      domain_separator: string;
      action_request: JSONValue;
      canonical_json: string;
      expected_sha256: string;
    };
  }>("docs/contracts/resolved-action-v1-vectors.json");
  if (fixture.schema_version !== "resolved-action-v1-vectors") throw new Error("unexpected ActionHash vector version");
  if (fixture.action_hash.domain_separator !== domain) throw new Error("ActionHash domain separator mismatch");

  const canonical = canonicalize(fixture.action_hash.action_request);
  if (canonical !== fixture.action_hash.canonical_json) {
    throw new Error(`canonical ActionRequest mismatch: ${canonical}`);
  }
  const digest = createHash("sha256").update(domain, "utf8").update(canonical, "utf8").digest("hex");
  if (digest !== fixture.action_hash.expected_sha256) {
    throw new Error(`ActionHash mismatch: got ${digest}, want ${fixture.action_hash.expected_sha256}`);
  }
  return digest;
}

function verifyUTF16Ordering(): void {
  const value = JSON.parse('{"\\uE000":1,"\\uD800\\uDC00":2}') as JSONValue;
  const actual = canonicalize(value);
  const expected = '{"𐀀":2,"":1}';
  if (actual !== expected) throw new Error(`UTF-16 key ordering mismatch: ${actual}`);
}

const count = verifyNumberVectors();
const digest = verifyResolvedActionHash();
verifyUTF16Ordering();
console.log(`EngageGuard TypeScript JCS verification passed: ${count} number vectors; ActionHash ${digest}`);
