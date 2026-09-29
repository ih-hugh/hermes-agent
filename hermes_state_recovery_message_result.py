"""Bounded private request/result codec for protected transcript batch acknowledgements.

The request preimage includes the original repair target. Mutable row annotations are
never used as durable lineage; the result records exact SQLite IDs in input order.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from hermes_state_recovery import RecoveryRefused

MAX_MESSAGE_BATCH_ROWS = 512
MAX_MESSAGE_PREIMAGE_BYTES = 1024 * 1024
MAX_MESSAGE_RESULT_BYTES = 64 * 1024
_MAX_SQLITE_ID = (1 << 63) - 1
_RESULT_SCHEMA = "hermes.message-write-result/v1"
_OUTPUT_ANNOTATIONS = frozenset({"_row_id", "_canonical_content"})


def _valid_id(value: object) -> bool:
    return type(value) is int and 0 < value <= _MAX_SQLITE_ID


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryRefused("invalid_recovery_write") from exc


def _pairs_unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryRefused("invalid_message_write_result")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class PreparedMessageBatch:
    canonical_bytes: bytes
    payload_sha256: str
    count: int

    def fresh_rows(self) -> list[dict]:
        """Return new mutable callback rows; rolled-back IDs cannot contaminate a retry."""
        entries = json.loads(self.canonical_bytes)
        rows = []
        for entry in entries:
            row = entry["row"]
            if entry["requested_target_id"] is not None:
                row["_row_id"] = entry["requested_target_id"]
            rows.append(row)
        return rows

    def matches_input(self, rows: list[dict]) -> bool:
        try:
            return prepare_message_batch(rows).canonical_bytes == self.canonical_bytes
        except RecoveryRefused:
            return False


def prepare_message_batch(rows: list[dict]) -> PreparedMessageBatch:
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_MESSAGE_BATCH_ROWS:
        raise RecoveryRefused("invalid_recovery_write")
    entries = []
    for row in rows:
        if not isinstance(row, dict) or any(not isinstance(key, str) for key in row):
            raise RecoveryRefused("invalid_recovery_write")
        target = row.get("_row_id")
        if target is not None and not _valid_id(target):
            raise RecoveryRefused("invalid_recovery_write")
        body = {key: value for key, value in row.items() if key not in _OUTPUT_ANNOTATIONS}
        entries.append({"row": body, "requested_target_id": target})
    encoded = _canonical_bytes(entries)
    if len(encoded) > MAX_MESSAGE_PREIMAGE_BYTES:
        raise RecoveryRefused("message_preimage_too_large")
    return PreparedMessageBatch(encoded, hashlib.sha256(encoded).hexdigest(), len(entries))


@dataclass(frozen=True, slots=True)
class MessageOutcomeV1:
    kind: Literal["inserted", "repaired", "adopted"]
    requested_target_id: int | None
    actual_message_id: int

    def __post_init__(self) -> None:
        if (type(self.kind) is not str or self.kind not in {"inserted", "repaired", "adopted"}
                or not _valid_id(self.actual_message_id)
                or self.requested_target_id is not None and not _valid_id(self.requested_target_id)
                or self.kind != "inserted" and self.requested_target_id is None):
            raise RecoveryRefused("invalid_message_write_result")


@dataclass(frozen=True, slots=True)
class MessageWriteResultV1:
    outcomes: tuple[MessageOutcomeV1, ...]

    @property
    def inserted_count(self) -> int:
        return sum(outcome.kind == "inserted" for outcome in self.outcomes)

    def to_ack_value(self) -> dict:
        if not 0 < len(self.outcomes) <= MAX_MESSAGE_BATCH_ROWS:
            raise RecoveryRefused("invalid_message_write_result")
        value = {"schema": _RESULT_SCHEMA, "inserted_count": self.inserted_count,
                 "outcomes": [{"kind": outcome.kind,
                               "requested_target_id": outcome.requested_target_id,
                               "actual_message_id": outcome.actual_message_id}
                              for outcome in self.outcomes]}
        # guarded_write currently persists json.dumps(result, sort_keys=True).
        if len(json.dumps(value, sort_keys=True).encode("utf-8")) > MAX_MESSAGE_RESULT_BYTES:
            raise RecoveryRefused("message_write_result_too_large")
        return value

    def to_json(self) -> str:
        return _canonical_bytes(self.to_ack_value()).decode("utf-8")


def read_message_result(raw: object) -> MessageWriteResultV1:
    """Strictly decode a committed result; the guard must pass bounded raw JSON."""
    if isinstance(raw, (str, bytes)):
        try:
            encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
            if len(encoded) > MAX_MESSAGE_RESULT_BYTES:
                raise RecoveryRefused("message_write_result_too_large")
            value = json.loads(encoded, object_pairs_hook=_pairs_unique,
                               parse_constant=lambda _value: (_ for _ in ()).throw(
                                   RecoveryRefused("invalid_message_write_result")))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RecoveryRefused("invalid_message_write_result") from exc
    else:
        value = raw
    if (not isinstance(value, dict) or set(value) != {"schema", "inserted_count", "outcomes"}
            or value["schema"] != _RESULT_SCHEMA
            or type(value["inserted_count"]) is not int
            or not isinstance(value["outcomes"], list)
            or not 0 < len(value["outcomes"]) <= MAX_MESSAGE_BATCH_ROWS):
        raise RecoveryRefused("invalid_message_write_result")
    outcomes = []
    for entry in value["outcomes"]:
        if not isinstance(entry, dict) or set(entry) != {
                "kind", "requested_target_id", "actual_message_id"}:
            raise RecoveryRefused("invalid_message_write_result")
        outcomes.append(MessageOutcomeV1(entry["kind"], entry["requested_target_id"],
                                         entry["actual_message_id"]))
    result = MessageWriteResultV1(tuple(outcomes))
    if value["inserted_count"] != result.inserted_count:
        raise RecoveryRefused("invalid_message_write_result")
    result.to_ack_value()
    return result
