#!/usr/bin/env python3
"""Cross-language RFC 8785 vector check for EngageGuard resolved ActionRequest."""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "engageguard/action-hash/v1\x00"


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def parse_json(raw: str) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=unique_object,
        parse_int=float,
        parse_float=float,
        parse_constant=reject_constant,
    )


def quote_string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("unpaired surrogate in JSON string") from exc
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonical_number(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("JCS cannot serialize a non-finite IEEE-754 number")
    if value == 0:
        return "0"

    rendered = repr(value).lower()
    if "e" not in rendered:
        return rendered[:-2] if rendered.endswith(".0") else rendered

    mantissa, exponent_text = rendered.split("e", 1)
    exponent = int(exponent_text)
    if mantissa.endswith(".0"):
        mantissa = mantissa[:-2]

    sign = ""
    if mantissa.startswith("-"):
        sign, mantissa = "-", mantissa[1:]

    if -6 <= exponent < 21:
        point = mantissa.find(".")
        if point < 0:
            point = len(mantissa)
        digits = mantissa.replace(".", "")
        decimal_position = point + exponent
        if decimal_position <= 0:
            return sign + "0." + ("0" * -decimal_position) + digits
        if decimal_position >= len(digits):
            return sign + digits + ("0" * (decimal_position - len(digits)))
        return sign + digits[:decimal_position] + "." + digits[decimal_position:]

    exponent_sign = "+" if exponent >= 0 else ""
    return sign + mantissa + "e" + exponent_sign + str(exponent)


def canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return quote_string(value)
    if isinstance(value, float):
        return canonical_number(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        try:
            keys = sorted(value, key=lambda item: item.encode("utf-16-be"))
        except UnicodeEncodeError as exc:
            raise ValueError("unpaired surrogate in JSON object key") from exc
        return "{" + ",".join(quote_string(key) + ":" + canonicalize(value[key]) for key in keys) + "}"
    raise TypeError(f"unsupported JSON value type: {type(value).__name__}")


def verify_number_vectors() -> int:
    fixture = json.loads((ROOT / "docs/contracts/jcs-number-vectors.v1.json").read_text(encoding="utf-8"))
    if fixture.get("schema_version") != "jcs-number-vectors.v1":
        raise ValueError("unexpected numeric vector fixture version")
    for vector in fixture["vectors"]:
        parsed = parse_json('{"n":' + vector["input"] + "}")
        actual = canonicalize(parsed)
        expected = '{"n":' + vector["canonical"] + "}"
        if actual != expected:
            raise AssertionError(f"JCS number {vector['input']}: got {actual}, want {expected}")
    return len(fixture["vectors"])


def verify_action_hash() -> str:
    fixture = json.loads((ROOT / "docs/contracts/resolved-action-v1-vectors.json").read_text(encoding="utf-8"))
    if fixture.get("schema_version") != "resolved-action-v1-vectors":
        raise ValueError("unexpected resolved ActionRequest vector fixture version")
    vector = fixture["action_hash"]
    if vector["domain_separator"] != DOMAIN:
        raise AssertionError("ActionHash domain separator mismatch")
    canonical = canonicalize(vector["action_request"])
    if canonical != vector["canonical_json"]:
        raise AssertionError(f"canonical ActionRequest mismatch: {canonical}")
    actual = hashlib.sha256(DOMAIN.encode("utf-8") + canonical.encode("utf-8")).hexdigest()
    if actual != vector["expected_sha256"]:
        raise AssertionError(f"ActionHash mismatch: got {actual}, want {vector['expected_sha256']}")
    return actual


def verify_unicode_ordering() -> None:
    value = parse_json('{"\\uE000":1,"\\uD800\\uDC00":2}')
    actual = canonicalize(value)
    expected = '{"𐀀":2,"":1}'
    if actual != expected:
        raise AssertionError(f"UTF-16 key ordering mismatch: {actual}")


def main() -> int:
    try:
        count = verify_number_vectors()
        digest = verify_action_hash()
        verify_unicode_ordering()
    except Exception as exc:  # CI should print the exact failing vector.
        print(f"EngageGuard JCS verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"EngageGuard Python JCS verification passed: {count} number vectors; ActionHash {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
