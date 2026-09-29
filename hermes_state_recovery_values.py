"""Hermes producer validation of closed recovery artifact values.

This module validates sealed evidence. It neither reads a store nor grants authority.
The source reader must compare these frozen inventories with PRAGMA table_info before
selecting any row and must supply the actual SQLite typeof for every source cell.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import struct
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal, TypeAlias, TypedDict, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    model_validator,
)

SCHEMA = "hermes.recovery.artifact-value/v1"
_INT = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_I64 = (1 << 63) - 1


def _columns(raw: str) -> tuple[tuple[str, str, int], ...]:
    return tuple(
        (name, kind, int(pk))
        for name, kind, pk in (entry.split(":") for entry in raw.split())
    )


SESSION_COLUMNS = _columns("""
id:TEXT:1 source:TEXT:0 user_id:TEXT:0 session_key:TEXT:0 chat_id:TEXT:0
chat_type:TEXT:0 thread_id:TEXT:0 display_name:TEXT:0 origin_json:TEXT:0
expiry_finalized:INTEGER:0 model:TEXT:0 model_config:TEXT:0 system_prompt:TEXT:0
system_prompt_hash:TEXT:0 parent_session_id:TEXT:0 started_at:REAL:0 ended_at:REAL:0
end_reason:TEXT:0 message_count:INTEGER:0 tool_call_count:INTEGER:0
input_tokens:INTEGER:0 output_tokens:INTEGER:0 cache_read_tokens:INTEGER:0
cache_write_tokens:INTEGER:0 reasoning_tokens:INTEGER:0 cwd:TEXT:0 git_branch:TEXT:0
git_repo_root:TEXT:0 git_metadata_generation:INTEGER:0 billing_provider:TEXT:0
billing_base_url:TEXT:0 billing_mode:TEXT:0 estimated_cost_usd:REAL:0
actual_cost_usd:REAL:0 cost_status:TEXT:0 cost_source:TEXT:0 pricing_version:TEXT:0
title:TEXT:0 title_source:TEXT:0 last_activity_at:REAL:0
last_activity_description:TEXT:0 last_activity_provenance:TEXT:0
api_call_count:INTEGER:0 handoff_state:TEXT:0 handoff_platform:TEXT:0
handoff_error:TEXT:0 compression_failure_cooldown_until:REAL:0
compression_failure_error:TEXT:0 compression_fallback_streak:INTEGER:0
compression_ineffective_count:INTEGER:0 compression_recovery_deadline:REAL:0
profile_name:TEXT:0 rewind_count:INTEGER:0 archived:INTEGER:0 pinned:INTEGER:0
hidden:INTEGER:0 last_read_at:REAL:0 tool_names:TEXT:0
""")
MESSAGE_COLUMNS = _columns("""
id:INTEGER:1 session_id:TEXT:0 role:TEXT:0 content:TEXT:0 tool_call_id:TEXT:0
tool_calls:TEXT:0 tool_name:TEXT:0 effect_disposition:TEXT:0 timestamp:REAL:0
token_count:INTEGER:0 finish_reason:TEXT:0 reasoning:TEXT:0
reasoning_content:TEXT:0 reasoning_details:TEXT:0 codex_reasoning_items:TEXT:0
codex_message_items:TEXT:0 platform_message_id:TEXT:0 observed:INTEGER:0
_compressed_summary:INTEGER:0 active:INTEGER:0 compacted:INTEGER:0
api_content:TEXT:0 display_kind:TEXT:0 display_metadata:TEXT:0
display_identity:BLOB:0 display_order:INTEGER:0
""")
MODEL_USAGE_COLUMNS = _columns("""
session_id:TEXT:1 model:TEXT:2 billing_provider:TEXT:3 billing_base_url:TEXT:4
billing_mode:TEXT:5 task:TEXT:6 api_call_count:INTEGER:0 input_tokens:INTEGER:0
output_tokens:INTEGER:0 cache_read_tokens:INTEGER:0 cache_write_tokens:INTEGER:0
reasoning_tokens:INTEGER:0 estimated_cost_usd:REAL:0 actual_cost_usd:REAL:0
cost_status:TEXT:0 cost_source:TEXT:0 first_seen:REAL:0 last_seen:REAL:0
""")

assert (len(SESSION_COLUMNS), len(MESSAGE_COLUMNS), len(MODEL_USAGE_COLUMNS)) == (
    58,
    26,
    18,
)


def encode_sqlite_cells(
    values: Sequence[object], storage_types: Sequence[str]
) -> list[list[str]]:
    """Encode one explicit SELECT row with same-row typeof results, without coercion."""
    if len(values) != len(storage_types):
        raise ValueError("SQLite value/typeof lengths differ")
    encoded: list[list[str]] = []
    for value, storage in zip(values, storage_types, strict=True):
        if storage == "null" and value is None:
            encoded.append(["n"])
        elif (
            storage == "integer"
            and type(value) is int
            and -(1 << 63) <= value <= _MAX_I64
        ):
            encoded.append(["i", str(value)])
        elif storage == "real" and type(value) is float and math.isfinite(value):
            encoded.append(["f", struct.pack(">d", value).hex()])
        elif storage == "text" and type(value) is str:
            value.encode("utf-8", errors="strict")
            encoded.append(["s", value])
        elif storage == "blob" and type(value) is bytes:
            encoded.append(["b", base64.b64encode(value).decode("ascii")])
        else:
            raise ValueError("SQLite cell does not match its storage class")
    return encoded


def decode_sqlite_cells(cells: object) -> tuple[object, ...]:
    if type(cells) is not list:
        raise ValueError("SQLite cells must be an array")
    decoded: list[object] = []
    for cell in cast(list[object], cells):
        if type(cell) is not list:
            raise ValueError("invalid SQLite cell")
        parts = cast(list[str], cell)
        if not parts or any(type(part) is not str for part in parts):
            raise ValueError("invalid SQLite cell")
        tag = parts[0]
        if tag == "n" and len(parts) == 1:
            decoded.append(None)
        elif tag == "i" and len(parts) == 2 and _INT.fullmatch(parts[1]):
            number = int(parts[1])
            if not -(1 << 63) <= number <= _MAX_I64:
                raise ValueError("SQLite integer out of range")
            decoded.append(number)
        elif tag == "f" and len(parts) == 2 and _HEX16.fullmatch(parts[1]):
            number = struct.unpack(">d", bytes.fromhex(parts[1]))[0]
            if not math.isfinite(number):
                raise ValueError("nonfinite SQLite real")
            decoded.append(number)
        elif tag == "s" and len(parts) == 2:
            parts[1].encode("utf-8", errors="strict")
            decoded.append(parts[1])
        elif tag == "b" and len(parts) == 2:
            try:
                blob = base64.b64decode(parts[1], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("invalid SQLite BLOB base64") from exc
            if base64.b64encode(blob).decode("ascii") != parts[1]:
                raise ValueError("noncanonical SQLite BLOB base64")
            decoded.append(blob)
        else:
            raise ValueError("invalid SQLite cell tag or payload")
    return tuple(decoded)


def _validate_fixed_cells(
    cells: object, columns: tuple[tuple[str, str, int], ...]
) -> None:
    decoded = decode_sqlite_cells(cells)
    if len(decoded) != len(columns):
        raise ValueError("wrong fixed SQLite vector length")
    for cell, (_, declared, pk) in zip(
        cast(list[list[str]], cells), columns, strict=True
    ):
        allowed = {
            "TEXT": {"s", "n"},
            "INTEGER": {"i", "n"},
            "REAL": {"f", "n"},
            "BLOB": {"b", "n"},
        }[declared]
        if cell[0] not in allowed or (pk and cell[0] == "n"):
            raise ValueError("SQLite cell conflicts with fixed schema")


class _Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, populate_by_name=True
    )

    schema_: Literal["hermes.recovery.artifact-value/v1"] = Field(alias="schema")


class LineageRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    write_id: str = Field(min_length=1, max_length=255)
    position: int = Field(ge=0, lt=512)


class SessionValue(_Value):
    record: Literal["session"]
    cells: list[list[str]]

    @model_validator(mode="after")
    def _cells(self):
        _validate_fixed_cells(self.cells, SESSION_COLUMNS)
        return self


class ModelUsageValue(_Value):
    record: Literal["model_usage"]
    cells: list[list[str]]

    @model_validator(mode="after")
    def _cells(self):
        _validate_fixed_cells(self.cells, MODEL_USAGE_COLUMNS)
        return self


class MessageValue(_Value):
    record: Literal["message"]
    cells: list[list[str]]
    lineage: list[LineageRef] = Field(min_length=1)

    @model_validator(mode="after")
    def _cells(self):
        _validate_fixed_cells(self.cells, MESSAGE_COLUMNS)
        return self


class WriteAckValue(_Value):
    record: Literal["write_ack"]
    write_id: str = Field(min_length=1, max_length=255)
    session_id: str = Field(min_length=1, max_length=255)
    run_id: str = Field(min_length=1, max_length=255)
    generation: Literal[0, 1]
    mutation: Literal["message", "session", "completion"]
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: Literal["committed"]
    ack_revision: int = Field(gt=0)
    result_json: str


class SendValue(_Value):
    record: Literal["send"]
    attempt_id: str = Field(min_length=1, max_length=255)
    run_id: str = Field(min_length=1, max_length=255)
    producer_id: str = Field(min_length=1, max_length=255)
    sequence: int = Field(ge=0)
    state: Literal["accounted", "no_charge_proved"]
    delta_id: str = Field(min_length=1, max_length=255)
    reason: Literal["sdk_not_entered"] | None
    slot_state: Literal["committed", "no_charge"]
    slot_attempt_id: str = Field(min_length=1, max_length=255)
    slot_delta_id: str = Field(min_length=1, max_length=255)
    ack_revision: int | None
    payload_sha256: str | None
    payload_base64: str | None

    @model_validator(mode="after")
    def _reciprocal(self):
        if (
            self.slot_attempt_id != self.attempt_id
            or self.slot_delta_id != self.delta_id
        ):
            raise ValueError("send/slot identities disagree")
        if self.state == "accounted":
            if (
                self.slot_state != "committed"
                or self.reason is not None
                or type(self.ack_revision) is not int
                or self.ack_revision <= 0
                or type(self.payload_sha256) is not str
                or not _HEX64.fullmatch(self.payload_sha256)
                or type(self.payload_base64) is not str
            ):
                raise ValueError("accounted send lacks committed usage")
            raw = _canonical_payload(self.payload_base64, 65536)
            if hashlib.sha256(raw).hexdigest() != self.payload_sha256:
                raise ValueError("retained usage digest mismatch")
        elif (
            self.slot_state != "no_charge"
            or self.reason != "sdk_not_entered"
            or self.ack_revision is not None
            or self.payload_sha256 is not None
            or self.payload_base64 is not None
        ):
            raise ValueError("no-charge send has usage or lacks pre-SDK proof")
        return self


class InvocationValue(_Value):
    record: Literal["invocation"]
    invocation_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=255)
    run_id: str = Field(min_length=1, max_length=255)
    generation: Literal[0, 1]
    producer_id: str = Field(min_length=1, max_length=64)
    sequence: int = Field(ge=0, lt=16384)
    kind: Literal["create_environment", "execute"]
    state: Literal["returned"]
    create_invocation_id: str | None = None
    container_id: str | None = None
    container_attestation_sha256: str | None = None
    exit_code: int | None = None
    outcome_reason: None

    @model_validator(mode="after")
    def _outcome(self):
        if self.kind == "create_environment":
            if (
                self.create_invocation_id is not None
                or not self.container_id
                or not self.container_attestation_sha256
                or self.exit_code is not None
            ):
                raise ValueError("incomplete returned create")
        elif (
            not self.create_invocation_id
            or self.container_id is not None
            or self.container_attestation_sha256 is not None
            or type(self.exit_code) is not int
            or not -(2**31) <= self.exit_code < 2**31
        ):
            raise ValueError("incomplete returned execute")
        if self.container_attestation_sha256 is not None and not _HEX64.fullmatch(
            self.container_attestation_sha256
        ):
            raise ValueError("invalid container attestation")
        return self


ArtifactValue: TypeAlias = Annotated[
    SessionValue
    | ModelUsageValue
    | MessageValue
    | WriteAckValue
    | SendValue
    | InvocationValue,
    Field(discriminator="record"),
]
_VALUE_ADAPTER: TypeAdapter[ArtifactValue] = TypeAdapter(ArtifactValue)
_KIND_RECORDS = {
    "transcript": {"message"},
    "accounting": {"session", "model_usage", "write_ack"},
    "send_ledger": {"send"},
    "provider_invocations": {"invocation"},
}


def validate_artifact_value(kind: str, value: Mapping[str, object]) -> ArtifactValue:
    """Decode one complete closed value; outer ArtifactRow already hashes this object."""
    if kind not in _KIND_RECORDS:
        raise ValueError("unknown artifact kind or value")
    try:
        parsed = _VALUE_ADAPTER.validate_python(dict(value), strict=True)
    except (ValidationError, ValueError) as exc:
        raise ValueError("invalid semantic artifact value") from exc
    if parsed.record not in _KIND_RECORDS[kind]:
        raise ValueError("artifact record conflicts with section")
    return parsed


def _canonical_payload(value: str, maximum: int) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid retained payload encoding") from exc
    if not 0 < len(raw) <= maximum or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("noncanonical or oversized retained payload")
    return raw


class RetainedUsageValue(TypedDict):
    write_id: str
    attempt_id: str
    generation: int
    model: str
    billing_provider: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    reasoning_tokens: int
    estimated_cost_usd: float | int
    actual_cost_usd: float | int | None
    cost_status: str | None
    cost_source: str | None
    pricing_version: str | None
    billing_base_url: str | None
    billing_mode: str | None
    api_call_count: int


def decode_retained_usage(send: SendValue) -> RetainedUsageValue:
    """Decode the complete canonical payload with the actual Hermes UsageDelta codec."""
    from dataclasses import asdict
    from hermes_state_usage import UsageDelta

    if (
        send.state != "accounted"
        or send.payload_base64 is None
        or send.payload_sha256 is None
    ):
        raise ValueError("send has no acknowledged usage")
    raw = _canonical_payload(send.payload_base64, 65536)
    try:
        delta = UsageDelta.from_canonical_bytes(raw, send.payload_sha256)
    except Exception as exc:
        raise ValueError("invalid retained UsageDelta") from exc
    if delta.attempt_id != send.attempt_id or delta.write_id != send.delta_id:
        raise ValueError("retained usage identity differs from send")
    if delta.model == "unknown" or delta.billing_provider == "unknown":
        raise ValueError("unknown retained usage route")
    if delta.estimated_cost_usd is None:
        raise ValueError("accounted send lacks estimated cost evidence")
    return cast(RetainedUsageValue, asdict(delta))


class SemanticContext(BaseModel):
    """Receipt-derived claims required to check included crosslinks, not source completeness."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    session_id: str = Field(min_length=1, max_length=255)
    members: tuple[tuple[str, Literal[0, 1]], ...] = Field(min_length=1, max_length=2)
    provider_container_id: str | None = Field(
        default=None, min_length=1, max_length=255
    )
    provider_attestation_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    no_calls: bool

    @model_validator(mode="after")
    def _members(self):
        if (
            [generation for _, generation in self.members]
            != list(range(len(self.members)))
            or len({run_id for run_id, _ in self.members}) != len(self.members)
            or any(not run_id or len(run_id) > 255 for run_id, _ in self.members)
        ):
            raise ValueError("invalid ordered member context")
        if (self.provider_container_id is None) != (
            self.provider_attestation_sha256 is None
        ):
            raise ValueError("partial provider binding")
        return self


class PartialSemanticCheck(BaseModel):
    """Internal consistency only; never a complete seal or source-scan proof."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    complete_source_proof: Literal[False] = False
    message_count: int
    write_ack_count: int
    send_count: int
    invocation_count: int
    accounted_api_calls: int
    actual_cost_usd: float | None
    route_replay_complete: Literal[False] = False


class MessageOutcomeValue(TypedDict):
    kind: Literal["inserted", "repaired", "adopted"]
    requested_target_id: int | None
    actual_message_id: int


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("invalid canonical semantic JSON") from exc


def _stored_ack_json(raw: str) -> object:
    """Preserve exactly the guarded writer's default json.dumps text."""
    if (
        type(raw) is not str
        or not 0 < len(raw.encode("utf-8", errors="strict")) <= 1024 * 1024
    ):
        raise ValueError("invalid stored acknowledgement text")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate acknowledgement key")
            result[key] = item
        return result

    def nonfinite(_token: str) -> object:
        raise ValueError("nonfinite acknowledgement")

    try:
        value: object = json.loads(
            raw, object_pairs_hook=unique, parse_constant=nonfinite
        )
        if json.dumps(value, sort_keys=True) != raw:
            raise ValueError("noncanonical writer acknowledgement")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid acknowledgement JSON") from exc
    return value


def _message_outcomes(raw: str | None) -> tuple[MessageOutcomeValue, ...]:
    """Require the existing protected message-result codec and canonical retained text."""
    from hermes_state_recovery_message_result import read_message_result

    if type(raw) is not str:
        raise ValueError("missing message acknowledgement")
    try:
        result = read_message_result(raw)
    except Exception as exc:
        raise ValueError("invalid message acknowledgement") from exc
    if json.dumps(result.to_ack_value(), sort_keys=True) != raw:
        raise ValueError("noncanonical message acknowledgement")
    return tuple(
        {
            "kind": outcome.kind,
            "requested_target_id": outcome.requested_target_id,
            "actual_message_id": outcome.actual_message_id,
        }
        for outcome in result.outcomes
    )


CounterName: TypeAlias = Literal[
    "api_call_count",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
]
_COUNTERS: tuple[CounterName, ...] = (
    "api_call_count",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
)


def _row_int(row: Mapping[str, object], name: str) -> int:
    value = row[name]
    if type(value) is not int or not 0 <= value <= _MAX_I64:
        raise ValueError("invalid SQLite usage counter")
    return value


def _row_cost(row: Mapping[str, object], name: str) -> float | int | None:
    value = row[name]
    if value is None:
        return None
    if (
        type(value) not in (int, float)
        or not math.isfinite(cast(float | int, value))
        or cast(float | int, value) < 0
    ):
        raise ValueError("invalid SQLite usage cost")
    return cast(float | int, value)


def verify_artifact_crosslinks(
    sections: Mapping[str, Sequence[Mapping[str, object]]],
    context: SemanticContext,
) -> PartialSemanticCheck:
    """Check included rows and bounded aggregate sums; H still attests the DB scan.

    Full per-route replay needs the original pre-send session route. A final session row
    alone cannot reconstruct every SQL COALESCE fallback, so this result is expressly
    partial even when all included links and aggregate counters match.
    """
    if set(sections) != set(_KIND_RECORDS):
        raise ValueError("all four closed artifact sections are required")
    total_bytes = 0
    parsed: dict[str, list[ArtifactValue]] = {}
    for kind, values in sections.items():
        if type(values) not in (list, tuple):
            raise ValueError("artifact section must be ordered")
        parsed[kind] = []
        for value in values:
            encoded = _canonical_json(value)
            total_bytes += len(encoded)
            if total_bytes > 16 * 1024 * 1024:
                raise ValueError("semantic snapshot exceeds total bound")
            parsed[kind].append(validate_artifact_value(kind, value))
    if len(parsed["transcript"]) > 100_000:
        raise ValueError("too many transcript rows")
    if (
        sum(len(_canonical_json(value)) for value in sections["accounting"])
        > 1024 * 1024
    ):
        raise ValueError(
            "session, model and full write-ack inventory exceeds accounting bound"
        )
    members = dict(context.members)
    accounting = parsed["accounting"]
    if not accounting or type(accounting[0]) is not SessionValue:
        raise ValueError("accounting must begin with one session")
    session_rows = [value for value in accounting if type(value) is SessionValue]
    if len(session_rows) != 1:
        raise ValueError("accounting must include exactly one session")
    session = dict(
        zip(
            (name for name, _, _ in SESSION_COLUMNS),
            decode_sqlite_cells(session_rows[0].cells),
            strict=True,
        )
    )
    if session["id"] != context.session_id:
        raise ValueError("accounting session differs from receipt")
    model_rows: list[dict[str, object]] = []
    ack_rows: list[WriteAckValue] = []
    phase = "model"
    previous_model: tuple[str, ...] | None = None
    previous_ack = 0
    all_revisions: set[int] = set()
    ack_ids: set[str] = set()
    outcomes: dict[tuple[str, int], tuple[WriteAckValue, MessageOutcomeValue]] = {}
    for value in accounting[1:]:
        if type(value) is ModelUsageValue and phase == "model":
            row = dict(
                zip(
                    (name for name, _, _ in MODEL_USAGE_COLUMNS),
                    decode_sqlite_cells(value.cells),
                    strict=True,
                )
            )
            key = tuple(row[name] for name, _, pk in MODEL_USAGE_COLUMNS if pk)
            if row["session_id"] != context.session_id or any(
                type(item) is not str for item in key
            ):
                raise ValueError("model row scope or key invalid")
            if previous_model is not None and key <= previous_model:
                raise ValueError("model rows out of primary-key order")
            previous_model = cast(tuple[str, ...], key)
            model_rows.append(row)
        elif type(value) is WriteAckValue:
            phase = "ack"
            if (
                value.session_id != context.session_id
                or members.get(value.run_id) != value.generation
                or value.ack_revision <= previous_ack
                or value.write_id in ack_ids
            ):
                raise ValueError("write ack scope, member or revision differs")
            ack_ids.add(value.write_id)
            _stored_ack_json(value.result_json)
            previous_ack = value.ack_revision
            all_revisions.add(value.ack_revision)
            ack_rows.append(value)
            if value.mutation == "message":
                for position, outcome in enumerate(
                    _message_outcomes(value.result_json)
                ):
                    outcomes[(value.write_id, position)] = (value, outcome)
        else:
            raise ValueError("accounting record order invalid")
    seen_messages: set[int] = set()
    seen_outcomes: set[tuple[str, int]] = set()
    previous_message = 0
    for value in parsed["transcript"]:
        assert type(value) is MessageValue
        message_id, session_id = decode_sqlite_cells(value.cells)[:2]
        if (
            type(message_id) is not int
            or message_id <= previous_message
            or session_id != context.session_id
        ):
            raise ValueError("message ID order or session differs")
        previous_message = message_id
        seen_messages.add(message_id)
        previous_lineage: tuple[int, int] | None = None
        inserted = 0
        for lineage_position, ref in enumerate(value.lineage):
            identity = (ref.write_id, ref.position)
            if identity in seen_outcomes or identity not in outcomes:
                raise ValueError("missing, duplicate or foreign message lineage")
            ack, outcome = outcomes[identity]
            order = (ack.ack_revision, ref.position)
            if previous_lineage is not None and order <= previous_lineage:
                raise ValueError("message lineage out of commit order")
            previous_lineage = order
            if outcome["actual_message_id"] != message_id:
                raise ValueError("lineage outcome points to another message")
            if outcome["kind"] == "inserted":
                if inserted or lineage_position != 0:
                    raise ValueError("duplicate message origin")
                inserted += 1
            elif inserted != 1 or outcome["requested_target_id"] != message_id:
                raise ValueError("repair/adoption lacks exact earlier origin")
            seen_outcomes.add(identity)
        if inserted != 1:
            raise ValueError("message lacks one insertion origin")
    if seen_outcomes != set(outcomes):
        raise ValueError("unmapped committed message acknowledgement outcome")

    sends = parsed["send_ledger"]
    if context.no_calls != (len(sends) == 0):
        raise ValueError("no_calls conflicts with admitted sends")
    previous_send: tuple[int, int] | None = None
    next_sequence = {run_id: 1 for run_id in members}
    attempt_ids: set[str] = set()
    delta_ids: set[str] = set()
    accounted: list[tuple[int, RetainedUsageValue]] = []
    for value in sends:
        assert type(value) is SendValue
        generation = members.get(value.run_id)
        if generation is None or value.sequence != next_sequence[value.run_id]:
            raise ValueError("send member or sequence invalid")
        if value.attempt_id in attempt_ids or value.delta_id in delta_ids:
            raise ValueError("duplicate physical send or usage slot")
        attempt_ids.add(value.attempt_id)
        delta_ids.add(value.delta_id)
        next_sequence[value.run_id] += 1
        order = (generation, value.sequence)
        if previous_send is not None and order <= previous_send:
            raise ValueError("send ledger out of member/sequence order")
        previous_send = order
        if value.state == "accounted":
            revision = value.ack_revision
            if type(revision) is not int or revision in all_revisions:
                raise ValueError("duplicate committed revision")
            all_revisions.add(revision)
            delta = decode_retained_usage(value)
            if delta["generation"] != generation:
                raise ValueError("retained usage generation differs")
            accounted.append((revision, delta))
    accounted.sort(key=lambda pair: pair[0])
    totals: dict[str, int] = {name: 0 for name in _COUNTERS}
    estimated, known_actual = 0.0, 0.0
    any_actual = False
    for _, delta in accounted:
        for name in _COUNTERS:
            totals[name] += delta[name]
            if totals[name] > _MAX_I64:
                raise ValueError("aggregate usage counter overflow")
        estimated += delta["estimated_cost_usd"]
        if delta["actual_cost_usd"] is not None:
            known_actual += delta["actual_cost_usd"]
            any_actual = True
    if any(_row_int(session, name) != totals[name] for name in _COUNTERS):
        raise ValueError("session usage aggregate differs from retained deltas")
    session_estimated = _row_cost(session, "estimated_cost_usd")
    session_actual = _row_cost(session, "actual_cost_usd")
    if accounted and session_estimated != estimated:
        raise ValueError("session estimated cost differs from retained deltas")
    if not accounted and session_estimated not in (None, 0, 0.0):
        raise ValueError("no-call session has estimated cost")
    if any_actual and session_actual != known_actual:
        raise ValueError("session actual cost sum differs from known deltas")
    if not any_actual and session_actual not in (None, 0, 0.0):
        raise ValueError("session actual cost has no retained basis")
    for name in _COUNTERS:
        if sum(_row_int(row, name) for row in model_rows) != totals[name]:
            raise ValueError("per-model usage aggregate differs")
    if not accounted and model_rows:
        raise ValueError("model rows exist without accounted sends")

    invocations = parsed["provider_invocations"]
    create: InvocationValue | None = None
    invocation_ids: set[str] = set()
    for sequence, value in enumerate(invocations):
        assert type(value) is InvocationValue
        if (
            value.session_id != context.session_id
            or value.sequence != sequence
            or members.get(value.run_id) != value.generation
        ):
            raise ValueError("provider invocation scope, member or sequence differs")
        if value.invocation_id in invocation_ids:
            raise ValueError("duplicate provider invocation ID")
        invocation_ids.add(value.invocation_id)
        if value.kind == "create_environment":
            if create is not None or sequence != 0:
                raise ValueError("provider has duplicate or late create")
            if (
                value.container_id != context.provider_container_id
                or value.container_attestation_sha256
                != context.provider_attestation_sha256
            ):
                raise ValueError("provider create differs from receipt binding")
            create = value
        elif create is None or value.create_invocation_id != create.invocation_id:
            raise ValueError("execute does not cite the one returned create")
    if (create is None) != (context.provider_container_id is None):
        raise ValueError("provider invocation inventory differs from binding")
    return PartialSemanticCheck(
        message_count=len(seen_messages),
        write_ack_count=len(ack_rows),
        send_count=len(sends),
        invocation_count=len(invocations),
        accounted_api_calls=len(accounted),
        actual_cost_usd=known_actual
        if accounted
        and len(accounted)
        == sum(delta["actual_cost_usd"] is not None for _, delta in accounted)
        else None,
    )
