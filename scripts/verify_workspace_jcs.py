#!/usr/bin/env python3
"""Cross-check the fixed all-string WorkspaceWrite v0.1 subset, NOT generic JCS."""
import hashlib
import json
from pathlib import Path

FIELDS = frozenset({
    "schema_version", "tenant_id", "subject_id", "agent_id",
    "operation_id", "capability_id", "tool_binding_digest",
    "policy_version", "audience", "workspace_id",
    "relative_path", "content_digest",
})
DOMAIN = b"engageguard/action-hash/v1\\x00"


def reject_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate fixture key: {key}")
        obj[key] = value
    return obj


def main():
    fixture_path = Path(__file__).resolve().parent.parent / "testdata" / "workspace-actionhash-v01.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    assert fixture["schema_version"] == "workspace-actionhash-fixtures.v0.1"
    assert fixture["domain_separator"] == r"engageguard/action-hash/v1\\u0000"
    assert len(fixture["vectors"]) == 4
    for vector in fixture["vectors"]:
        action = vector["action"]
        assert set(action) == FIELDS, vector["name"]
        assert all(isinstance(value, str) for value in action.values()), vector["name"]
        # These fixed ASCII field names have the same UTF-16 and Unicode code-point order.
        encoded = json.dumps(action, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        canonical = encoded.decode("utf-8")
        assert canonical == vector["canonical"], vector["name"]
        digest = hashlib.sha256(DOMAIN + encoded).hexdigest()
        assert digest == vector["sha256"], vector["name"]
        print(f"python WorkspaceWrite JCS-subset OK: {vector['name']}")


if __name__ == "__main__":
    main()
