"""Pure canonical bytes and bounded hashes for sealed recovery artifacts.

The finalizer owns storage and transaction timing. These helpers never read live state.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TypeAlias, cast

from pydantic import BaseModel

MAX_RESPONSE_BYTES = 128 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_ACCOUNTING_BYTES = 1024 * 1024
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_ROUTE_PAGES = 4096
MAX_TRANSCRIPT_ROWS = 100_000
MAX_TRANSCRIPT_PAGE_ROWS = 64
MAX_OTHER_PAGE_ROWS = 1024

Json: TypeAlias = None | bool | int | float | str | list["Json"] | dict[str, "Json"]

SECTION_TAGS = {
    "transcript": "hermes.recovery.transcript/v1",
    "accounting": "hermes.recovery.accounting/v1",
    "send_ledger": "hermes.recovery.send-ledger/v1",
    "provider_invocations": "hermes.recovery.provider-invocations/v1",
}


def _pairs_unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _nonfinite(token: str) -> object:
    raise ValueError("nonfinite JSON number")


def _finite_tree(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite JSON number")
    if isinstance(value, Mapping):
        for key, item in cast(Mapping[object, object], value).items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _finite_tree(item)
    elif isinstance(value, (list, tuple)):
        for item in cast(list[object] | tuple[object, ...], value):
            _finite_tree(item)


def strict_json_loads(raw: bytes, *, max_bytes: int = MAX_RESPONSE_BYTES) -> object:
    """Reject duplicate keys, nonfinite values, invalid UTF-8 and oversized JSON."""
    if len(raw) > max_bytes:
        raise ValueError("encoded JSON exceeds its byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_unique,
            parse_constant=_nonfinite,
        )
        _finite_tree(value)
        canonical_json_bytes(value)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid UTF-8 JSON") from error
    return value


def canonical_json_bytes(value: object) -> bytes:
    """The exact UTF-8 JSON encoding used by both recovery peers."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    _finite_tree(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, UnicodeError, ValueError) as error:
        raise ValueError("value cannot be encoded as canonical JSON") from error


def bounded_response_bytes(value: object) -> bytes:
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise ValueError("full encoded recovery response exceeds 128 KiB")
    return encoded


def domain_sha256(tag: str, payload: bytes) -> str:
    if not tag.startswith("hermes.recovery.") or not tag.endswith("/v1"):
        raise ValueError("unknown recovery hash domain")
    return hashlib.sha256(tag.encode("ascii") + b"\n" + payload).hexdigest()


def document_sha256(tag: str, value: object) -> str:
    return domain_sha256(tag, canonical_json_bytes(value) + b"\n")


@dataclass(frozen=True)
class HashedRows:
    sha256: str
    count: int
    byte_count: int


def hash_rows(
    kind: str,
    rows: Iterable[object],
    *,
    max_rows: int | None = None,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> HashedRows:
    """Hash one ordered row stream without accumulating its contents."""
    tag = SECTION_TAGS[kind]
    digest = hashlib.sha256(tag.encode("ascii") + b"\n")
    count = byte_count = 0
    for row in rows:
        line = canonical_json_bytes(row) + b"\n"
        count += 1
        byte_count += len(line)
        if (max_rows is not None and count > max_rows) or byte_count > max_bytes:
            raise ValueError("sealed section exceeds its fixed bound")
        digest.update(line)
    return HashedRows(digest.hexdigest(), count, byte_count)


def manifest_sha256(header: object, descriptors: Iterable[object]) -> HashedRows:
    digest = hashlib.sha256(b"hermes.recovery.manifest/v1\n")
    first = canonical_json_bytes(header) + b"\n"
    digest.update(first)
    byte_count = len(first)
    count = 0
    for descriptor in descriptors:
        line = canonical_json_bytes(descriptor) + b"\n"
        byte_count += len(line)
        count += 1
        if byte_count > MAX_SNAPSHOT_BYTES or count > MAX_ROUTE_PAGES:
            raise ValueError("sealed manifest exceeds its fixed bound")
        digest.update(line)
    return HashedRows(digest.hexdigest(), count, byte_count)
