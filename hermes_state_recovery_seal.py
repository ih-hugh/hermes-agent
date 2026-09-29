"""One bounded, immutable finalization of a protected recovery session.

The provider readback is prepared outside the state.db writer. A successful
finalizer reads every source row and commits the receipt, pages and tombstone in
one BEGIN IMMEDIATE callback; a refusal leaves the committed close barrier.
"""

from __future__ import annotations

import base64
import hashlib
import math
import sqlite3
import time
import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, cast

from pydantic import JsonValue

from agent.recovery_context import current_incarnation
from gateway.platforms.api_server_recovery_artifacts import (
    MAX_ACCOUNTING_BYTES,
    MAX_RESPONSE_BYTES,
    MAX_ROUTE_PAGES,
    MAX_SNAPSHOT_BYTES,
    MAX_TRANSCRIPT_ROWS,
    SECTION_TAGS,
    bounded_response_bytes,
    canonical_json_bytes,
    document_sha256,
    hash_rows,
    manifest_sha256,
    strict_json_loads,
)
from gateway.platforms.api_server_recovery_contract import (
    AcknowledgedUsage,
    ArtifactKind,
    ArtifactRow,
    DataArtifactPage,
    DataBody,
    ManifestArtifactPage,
    ManifestHeader,
    PageDescriptor,
    ProviderBinding,
    SealReceipt,
    SealRequest,
    SealResult,
    SignedStatusWire,
    descriptor_for_body,
    receipt_sha256,
    verify_sealed_pages,
)
from hermes_state_recovery import (
    RecoveryRefused,
    RecoveryScope,
    RecoveryStore,
    membership_sha256,
)
from hermes_state_recovery_provider import (
    ProviderAdmissionValue,
    SelectedProviderCapture,
    iter_rows as iter_provider_rows,
    read_admission,
)
from hermes_state_recovery_values import (
    MESSAGE_COLUMNS,
    MODEL_USAGE_COLUMNS,
    SCHEMA as VALUE_SCHEMA,
    SESSION_COLUMNS,
    SemanticContext,
    decode_sqlite_cells,
    encode_sqlite_cells,
    validate_artifact_value,
    verify_artifact_crosslinks,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence
    from gateway.platforms.api_server_recovery_contract import RecoveryMember


_SEAL_SECONDS = 5.0
_MAX_SOURCE_ROW_BYTES = MAX_RESPONSE_BYTES
_MAX_ACK_RESULT_BYTES = 65_536
_MAX_SOURCE_ROWS = 100_000
_MAX_PRODUCER_METADATA_BYTES = MAX_SNAPSHOT_BYTES
_KINDS = cast(tuple[ArtifactKind, ...], tuple(SECTION_TAGS))
_EVIDENCE_ISSUER = object()
_PREPARED: weakref.WeakValueDictionary[int, PreparedProviderEvidence] = (
    weakref.WeakValueDictionary()
)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedProviderEvidence:
    """Verified readback from the exact selected plugin, never HTTP request data."""

    capture: SelectedProviderCapture = field(repr=False, compare=False)
    admission: ProviderAdmissionValue
    state: Literal["unused", "bound"]
    signed_status: SignedStatusWire
    signed_status_sha256: str
    container_id: str | None
    container_attestation_sha256: str | None
    _issuer: object = field(repr=False, compare=False)


def prepare_provider_evidence(
    capture: SelectedProviderCapture,
) -> PreparedProviderEvidence:
    """Read the selected provider's retained association outside the DB lock."""
    if type(capture) is not SelectedProviderCapture:
        raise RecoveryRefused("provider_selection_changed")
    provider = capture.require_selected()
    reader = getattr(provider, "read_recovery_binding_wire", None)
    if not callable(reader):
        raise RecoveryRefused("provider_readback_unavailable")
    try:
        raw = reader(capture.admission.canonical_bytes())
        if (
            type(raw).__name__ != "RecoveryProviderReadback"
            or type(raw).__module__.split(".")[-1] != "workspace_recovery"
        ):
            raise ValueError("unexpected provider readback type")
        admission = ProviderAdmissionValue.model_validate(
            raw.admission.model_dump(mode="json")
        )
        signed = SignedStatusWire.model_validate(
            raw.signed_status.model_dump(mode="json", by_alias=True)
        )
        if (
            admission.canonical_bytes() != capture.admission.canonical_bytes()
            or signed.status.reference != admission.reference
            or signed.status.session_id != admission.session_id
            or signed.status.state != raw.status_state
            or signed.status.revision != raw.status_revision
            or hashlib.sha256(canonical_json_bytes(signed)).hexdigest()
            != raw.signed_status_sha256
        ):
            raise ValueError("source binding changed")
        evidence = PreparedProviderEvidence(
            capture,
            admission,
            raw.state,
            signed,
            raw.signed_status_sha256,
            raw.container_id,
            raw.container_attestation_sha256,
            _EVIDENCE_ISSUER,
        )
        capture.require_selected()
        _PREPARED[id(evidence)] = evidence
        return evidence
    except RecoveryRefused:
        raise
    except Exception as exc:
        raise RecoveryRefused("provider_readback_invalid") from exc


class _Budget:
    """One active budget retained even if SessionDB retries the SQL callback."""

    def __init__(self, upstream_deadline: float | None):
        if upstream_deadline is not None and not math.isfinite(upstream_deadline):
            raise RecoveryRefused("seal_deadline_invalid")
        self.upstream_deadline = upstream_deadline
        self.active_deadline: float | None = None
        self.snapshot_bytes = 0
        self.accounting_bytes = 0
        self.producer_bytes = 0
        self._section_counts = {kind: 0 for kind in _KINDS}

    def start(self) -> None:
        now = time.monotonic()
        if self.active_deadline is None:
            self.active_deadline = now + _SEAL_SECONDS
        self.check()

    def check(self) -> None:
        now = time.monotonic()
        if (self.active_deadline is not None and now >= self.active_deadline) or (
            self.upstream_deadline is not None and now >= self.upstream_deadline
        ):
            raise RecoveryRefused("seal_deadline_exceeded")

    def progress(self) -> int:
        try:
            self.check()
        except RecoveryRefused:
            return 1
        return 0

    def preview_source(self, raw_bytes: int, kind: str) -> None:
        self.check()
        if (
            raw_bytes < 0
            or self.snapshot_bytes + raw_bytes > MAX_SNAPSHOT_BYTES
            or kind == "accounting"
            and self.accounting_bytes + raw_bytes > MAX_ACCOUNTING_BYTES
        ):
            raise RecoveryRefused("snapshot_oversized")

    def charge_value(self, kind: ArtifactKind, value: dict[str, object]) -> None:
        self.check()
        index = self._section_counts[kind]
        row = ArtifactRow(
            row_index=index,
            kind=kind,
            value=cast(dict[str, JsonValue], value),
            row_sha256=document_sha256(
                f"hermes.recovery.row/{kind}/v1",
                {"row_index": index, "kind": kind, "value": value},
            ),
        )
        size = len(canonical_json_bytes(row)) + 1
        if (
            self.snapshot_bytes + size > MAX_SNAPSHOT_BYTES
            or kind == "accounting"
            and self.accounting_bytes + size > MAX_ACCOUNTING_BYTES
        ):
            raise RecoveryRefused("snapshot_oversized")
        self.snapshot_bytes += size
        if kind == "accounting":
            self.accounting_bytes += size
        self._section_counts[kind] += 1

    def charge_producer_metadata(self, raw_bytes: int) -> None:
        self.check()
        if (
            raw_bytes < 0
            or self.producer_bytes + raw_bytes > _MAX_PRODUCER_METADATA_BYTES
        ):
            raise RecoveryRefused("producer_inventory_invalid")
        self.producer_bytes += raw_bytes


def _check_columns(
    conn: sqlite3.Connection, table: str, columns: tuple[tuple[str, str, int], ...]
) -> None:
    # `table` is a private constant, never request input.
    actual = tuple(
        (row[1], row[2].upper(), row[5])
        for row in conn.execute(f"PRAGMA table_info({table})")
    )
    if actual != columns:
        raise RecoveryRefused("source_schema_changed")


def _bounded_row(
    conn: sqlite3.Connection,
    table: str,
    columns: tuple[tuple[str, str, int], ...],
    where: str,
    params: tuple[object, ...],
    budget: _Budget,
    kind: str,
) -> list[list[str]]:
    """Measure each cell in SQLite before fetching one complete source row."""
    budget.check()
    names = tuple(name for name, _, _ in columns)
    metadata = ",".join(
        f'typeof("{name}"),length(substr(CAST("{name}" AS BLOB),1,?))' for name in names
    )
    meta = conn.execute(
        f"SELECT {metadata} FROM {table} WHERE {where}",
        (_MAX_SOURCE_ROW_BYTES + 1,) * len(names) + params,
    ).fetchone()
    if meta is None:
        raise RecoveryRefused("source_row_missing")
    total = 0
    for index in range(0, len(meta), 2):
        storage, length = meta[index : index + 2]
        if storage not in {"null", "integer", "real", "text", "blob"}:
            raise RecoveryRefused("source_row_invalid")
        if length is not None:
            if type(length) is not int or length > _MAX_SOURCE_ROW_BYTES:
                raise RecoveryRefused("source_row_oversized")
            total += length
        if total > _MAX_SOURCE_ROW_BYTES:
            raise RecoveryRefused("source_row_oversized")
    budget.preview_source(total, kind)
    selected = ",".join(f'"{name}"' for name in names)
    row = conn.execute(
        f"SELECT {selected} FROM {table} WHERE {where}", params
    ).fetchone()
    if row is None:
        raise RecoveryRefused("source_row_missing")
    try:
        cells = encode_sqlite_cells(row, meta[::2])
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RecoveryRefused("source_row_invalid") from exc
    budget.check()
    return cells


def _member_preflight(
    conn: sqlite3.Connection,
    store: RecoveryStore,
    scope: RecoveryScope,
    request: SealRequest,
    budget: _Budget,
) -> tuple[int, tuple[RecoveryMember, ...]]:
    session = conn.execute(
        "SELECT phase,revision,root_run_id,close_request_id,close_request_json,"
        "reason_codes_json,receipt_json FROM recovery_sessions "
        "WHERE session_id=? AND profile=? AND scope_digest=?",
        (scope.session_id, scope.profile, scope.scope_digest),
    ).fetchone()
    if session is None:
        raise RecoveryRefused("not_found")
    if (
        session[0] != "closing"
        or session[3] != request.request_id
        or session[4] != request.model_dump_json()
    ):
        raise RecoveryRefused("close_conflict")
    if session[6] is not None or session[5] != "[]":
        raise RecoveryRefused("seal_incomplete")
    rows = conn.execute(
        "SELECT run_id,generation,parent_run_id,request_sha256,producer_state,"
        "owner_incarnation,profile,scope_digest FROM recovery_members "
        "WHERE session_id=? ORDER BY generation LIMIT 3",
        (scope.session_id,),
    ).fetchall()
    try:
        members = tuple(store._member(row) for row in rows)
    except ValueError as exc:
        raise RecoveryRefused("missing_membership") from exc
    if (
        not 1 <= len(rows) <= 2
        or [row[1] for row in rows] != list(range(len(rows)))
        or tuple(row[0] for row in rows) != request.run_ids
        or membership_sha256(request.run_ids) != request.expected_membership_sha256
        or session[2] != request.run_ids[0]
        or members[0].parent_run_id is not None
        or len(members) == 2
        and members[1].parent_run_id != members[0].run_id
    ):
        raise RecoveryRefused("missing_membership")
    for row in rows:
        if (
            row[4] != "closed"
            or row[5] != current_incarnation()
            or (row[6], row[7]) != (scope.profile, scope.scope_digest)
        ):
            raise RecoveryRefused("lost_producer_owner")
        if (
            conn.execute(
                "SELECT 1 FROM recovery_root_done WHERE run_id=?", (row[0],)
            ).fetchone()
            is None
        ):
            raise RecoveryRefused("unclosed_producer")
        status_meta = conn.execute(
            "SELECT typeof(status_json),length(substr(CAST(status_json AS BLOB),1,4097)) "
            "FROM recovery_members WHERE run_id=?",
            (row[0],),
        ).fetchone()
        if (
            status_meta is None
            or status_meta[0] != "text"
            or type(status_meta[1]) is not int
            or not 0 < status_meta[1] <= 4096
        ):
            raise RecoveryRefused("status_barrier_missing")
        status_raw = conn.execute(
            "SELECT status_json FROM recovery_members WHERE run_id=?", (row[0],)
        ).fetchone()[0]
        try:
            status = strict_json_loads(status_raw.encode("utf-8"), max_bytes=4096)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise RecoveryRefused("status_barrier_missing") from exc
        if type(status) is not dict or cast(dict[str, object], status).get(
            "status"
        ) not in {
            "completed",
            "failed",
            "cancelled",
        }:
            raise RecoveryRefused("status_barrier_missing")
        count = conn.execute(
            "SELECT COUNT(*) FROM recovery_producers WHERE run_id=?", (row[0],)
        ).fetchone()[0]
        if type(count) is not int or count > _MAX_SOURCE_ROWS:
            raise RecoveryRefused("producer_inventory_invalid")
        closed_callbacks = 0
        last_state, last_rowid = "", 0
        for _ in range(count):
            budget.check()
            metadata = conn.execute(
                "SELECT rowid,substr(state,1,256),substr(producer_id,1,256),"
                "length(substr(CAST(producer_id AS BLOB),1,257)),"
                "length(substr(CAST(kind AS BLOB),1,257)),"
                "length(substr(CAST(state AS BLOB),1,257)),"
                "length(substr(CAST(owner_incarnation AS BLOB),1,257)) "
                "FROM recovery_producers INDEXED BY idx_recovery_producers_run_state "
                "WHERE run_id=? AND (state,rowid)>(?,?) "
                "ORDER BY state,rowid LIMIT 1",
                (row[0], last_state, last_rowid),
            ).fetchone()
            if (
                metadata is None
                or type(metadata[0]) is not int
                or type(metadata[1]) is not str
                or type(metadata[2]) is not str
                or any(
                    type(size) is not int or not 0 < size <= 255
                    for size in metadata[3:]
                )
            ):
                raise RecoveryRefused("producer_inventory_invalid")
            budget.charge_producer_metadata(sum(metadata[3:]) + 64)
            last_rowid, last_state = metadata[0], metadata[1]
            producer = conn.execute(
                "SELECT producer_id,kind,state,owner_incarnation "
                "FROM recovery_producers WHERE rowid=? AND run_id=?",
                (last_rowid, row[0]),
            ).fetchone()
            if (
                producer is None
                or producer[0] != metadata[2]
                or producer[2] != last_state
            ):
                raise RecoveryRefused("producer_inventory_invalid")
            producer_id, kind, state, owner = producer
            if (
                owner != current_incarnation()
                or kind not in {"executor", "tool", "sdk", "callback", "usage_write"}
                or state not in {"closed", "cancelled"}
            ):
                raise RecoveryRefused("unclosed_producer")
            if (
                state == "cancelled"
                and conn.execute(
                    "SELECT 1 FROM recovery_sends WHERE producer_id=? LIMIT 1",
                    (producer_id,),
                ).fetchone()
                is not None
            ):
                raise RecoveryRefused("unclosed_producer")
            if kind == "callback" and state == "closed":
                closed_callbacks += 1
        if closed_callbacks == 0:
            raise RecoveryRefused("status_barrier_missing")
    return int(session[1]), members


def _ack_values(
    conn: sqlite3.Connection, scope: RecoveryScope, budget: _Budget
) -> tuple[list[dict[str, object]], dict[int, list[dict[str, object]]]]:
    from hermes_state_recovery_message_result import read_message_result

    if (
        conn.execute(
            "SELECT 1 FROM recovery_write_acks WHERE session_id=? "
            "AND (state!='committed' OR typeof(ack_revision)!='integer' OR ack_revision<=0) LIMIT 1",
            (scope.session_id,),
        ).fetchone()
        is not None
    ):
        raise RecoveryRefused("failed_usage_acknowledgement")
    result: list[dict[str, object]] = []
    lineage: dict[int, list[dict[str, object]]] = {}
    revision, write_id = 0, ""
    while True:
        budget.check()
        metadata = conn.execute(
            "SELECT ack_revision,substr(write_id,1,256),"
            "length(substr(CAST(result_json AS BLOB),1,?)),"
            "typeof(result_json),length(substr(CAST(run_id AS BLOB),1,257)),"
            "length(substr(CAST(write_id AS BLOB),1,257)) "
            "FROM recovery_write_acks WHERE session_id=? "
            "AND (ack_revision,write_id)>(?,?) "
            "ORDER BY ack_revision,write_id LIMIT 1",
            (_MAX_ACK_RESULT_BYTES + 1, scope.session_id, revision, write_id),
        ).fetchone()
        if metadata is None:
            break
        if (
            len(result) >= _MAX_SOURCE_ROWS
            or type(metadata[0]) is not int
            or metadata[0] <= revision
            or type(metadata[1]) is not str
            or not 0 < len(metadata[1]) <= 255
            or metadata[3] != "text"
            or type(metadata[2]) is not int
            or not 0 < metadata[2] <= _MAX_ACK_RESULT_BYTES
            or any(
                type(size) is not int or not 0 < size <= 255 for size in metadata[4:]
            )
        ):
            raise RecoveryRefused("write_ack_inventory_invalid")
        budget.preview_source(metadata[2] + metadata[4] + metadata[5], "accounting")
        revision, write_id = metadata[:2]
        row = conn.execute(
            "SELECT write_id,session_id,run_id,generation,mutation,payload_sha256,"
            "state,ack_revision,result_json FROM recovery_write_acks "
            "WHERE session_id=? AND ack_revision=? AND write_id=?",
            (scope.session_id, revision, write_id),
        ).fetchone()
        if row is None or row[6] != "committed":
            raise RecoveryRefused("write_ack_inventory_invalid")
        value = dict(
            zip(
                (
                    "write_id",
                    "session_id",
                    "run_id",
                    "generation",
                    "mutation",
                    "payload_sha256",
                    "state",
                    "ack_revision",
                    "result_json",
                ),
                row,
                strict=True,
            )
        )
        value.update(schema=VALUE_SCHEMA, record="write_ack")
        try:
            validate_artifact_value("accounting", value)
            if row[4] == "message":
                message_result = read_message_result(row[8])
                for position, outcome in enumerate(message_result.outcomes):
                    lineage.setdefault(outcome.actual_message_id, []).append({
                        "write_id": write_id,
                        "position": position,
                    })
        except (ValueError, TypeError) as exc:
            raise RecoveryRefused("write_ack_inventory_invalid") from exc
        result.append(value)
        budget.charge_value("accounting", value)
    return result, lineage


def _source_values(
    conn: sqlite3.Connection,
    scope: RecoveryScope,
    budget: _Budget,
    lineage: dict[int, list[dict[str, object]]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    for table, columns in (
        ("sessions", SESSION_COLUMNS),
        ("messages", MESSAGE_COLUMNS),
        ("session_model_usage", MODEL_USAGE_COLUMNS),
    ):
        _check_columns(conn, table, columns)
    session_cells = _bounded_row(
        conn,
        "sessions",
        SESSION_COLUMNS,
        "id=?",
        (scope.session_id,),
        budget,
        "accounting",
    )
    accounting: list[dict[str, object]] = [
        {"schema": VALUE_SCHEMA, "record": "session", "cells": session_cells}
    ]
    budget.charge_value("accounting", accounting[0])
    model_key: tuple[str, str, str, str, str] | None = None
    while True:
        budget.check()
        where = "session_id=?"
        params: tuple[object, ...] = (scope.session_id,)
        if model_key is not None:
            where += " AND (model,billing_provider,billing_base_url,billing_mode,task)>(?,?,?,?,?)"
            params += model_key
        key = conn.execute(
            "SELECT substr(model,1,256),substr(billing_provider,1,256),"
            "substr(billing_base_url,1,256),substr(billing_mode,1,256),substr(task,1,256) "
            f"FROM session_model_usage WHERE {where} "
            "ORDER BY model,billing_provider,billing_base_url,billing_mode,task LIMIT 1",
            params,
        ).fetchone()
        if key is None:
            break
        if len(accounting) >= _MAX_SOURCE_ROWS or any(
            type(part) is not str or len(part) > 255 for part in key
        ):
            raise RecoveryRefused("model_usage_oversized")
        model_key = tuple(key)
        cells = _bounded_row(
            conn,
            "session_model_usage",
            MODEL_USAGE_COLUMNS,
            "session_id=? AND model=? AND billing_provider=? AND billing_base_url=? "
            "AND billing_mode=? AND task=?",
            (scope.session_id, *model_key),
            budget,
            "accounting",
        )
        value: dict[str, object] = {
            "schema": VALUE_SCHEMA,
            "record": "model_usage",
            "cells": cells,
        }
        budget.charge_value("accounting", value)
        accounting.append(value)
    transcript: list[dict[str, object]] = []
    if (
        conn.execute(
            "SELECT 1 FROM messages WHERE session_id=? AND id<=0 LIMIT 1",
            (scope.session_id,),
        ).fetchone()
        is not None
    ):
        raise RecoveryRefused("transcript_inventory_invalid")
    previous_id = 0
    while True:
        budget.check()
        found = conn.execute(
            "SELECT id FROM messages WHERE session_id=? AND id>? ORDER BY id LIMIT 1",
            (scope.session_id, previous_id),
        ).fetchone()
        if found is None:
            break
        if (
            len(transcript) >= MAX_TRANSCRIPT_ROWS
            or type(found[0]) is not int
            or found[0] <= previous_id
        ):
            raise RecoveryRefused("transcript_oversized")
        previous_id = found[0]
        refs = lineage.pop(previous_id, None)
        if not refs:
            raise RecoveryRefused("message_lineage_missing")
        cells = _bounded_row(
            conn,
            "messages",
            MESSAGE_COLUMNS,
            "session_id=? AND id=?",
            (scope.session_id, previous_id),
            budget,
            "transcript",
        )
        value: dict[str, object] = {
            "schema": VALUE_SCHEMA,
            "record": "message",
            "cells": cells,
            "lineage": refs,
        }
        try:
            validate_artifact_value("transcript", value)
        except ValueError as exc:
            raise RecoveryRefused("message_lineage_invalid") from exc
        transcript.append(value)
        budget.charge_value("transcript", value)
    if lineage:
        raise RecoveryRefused("message_lineage_invalid")
    return transcript, accounting


def _send_values(
    conn: sqlite3.Connection,
    scope: RecoveryScope,
    members: tuple[RecoveryMember, ...],
    budget: _Budget,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for member in members:
        if (
            conn.execute(
                "SELECT 1 FROM recovery_sends WHERE run_id=? AND sequence<=0 LIMIT 1",
                (member.run_id,),
            ).fetchone()
            is not None
        ):
            raise RecoveryRefused("send_inventory_invalid")
        sequence = 0
        while True:
            budget.check()
            next_row = conn.execute(
                "SELECT sequence FROM recovery_sends WHERE run_id=? AND sequence>? "
                "ORDER BY sequence LIMIT 1",
                (member.run_id, sequence),
            ).fetchone()
            if next_row is None:
                break
            if type(next_row[0]) is not int or next_row[0] != sequence + 1:
                raise RecoveryRefused("send_inventory_invalid")
            candidate_sequence = next_row[0]
            lengths = conn.execute(
                "SELECT "
                + ",".join(
                    f"length(substr(CAST({name} AS BLOB),1,257))"
                    for name in (
                        "a.attempt_id",
                        "a.producer_id",
                        "a.delta_id",
                        "a.state",
                        "a.reason",
                        "s.delta_id",
                        "s.attempt_id",
                        "s.state",
                        "s.payload_sha256",
                        "p.run_id",
                        "p.kind",
                        "p.state",
                        "p.owner_incarnation",
                    )
                )
                + ",length(substr(s.payload_json,1,65537)),substr(a.state,1,256) "
                "FROM recovery_sends a LEFT JOIN recovery_usage_slots s USING(attempt_id) "
                "LEFT JOIN recovery_producers p ON p.producer_id=a.producer_id "
                "WHERE a.run_id=? AND a.sequence=?",
                (member.run_id, candidate_sequence),
            ).fetchone()
            if (
                lengths is None
                or any(
                    type(size) is not int or size > 255
                    for size in lengths[:4] + lengths[5:8] + lengths[9:13]
                )
                or lengths[14] not in {"accounted", "no_charge_proved"}
                or (
                    lengths[8] != 64
                    if lengths[14] == "accounted"
                    else lengths[8] is not None
                )
                or lengths[4] is not None
                and (type(lengths[4]) is not int or lengths[4] > 255)
                or lengths[13] is not None
                and (type(lengths[13]) is not int or lengths[13] > 65_536)
            ):
                raise RecoveryRefused("send_inventory_invalid")
            budget.preview_source(
                sum(size or 0 for size in lengths[:14]), "send_ledger"
            )
            meta = conn.execute(
                "SELECT a.sequence,a.attempt_id,a.producer_id,a.delta_id,a.state,a.reason,"
                "s.delta_id,s.attempt_id,s.state,s.ack_revision,s.payload_sha256,"
                "length(substr(s.payload_json,1,65537)),typeof(s.payload_json),"
                "p.run_id,p.kind,p.state,p.owner_incarnation "
                "FROM recovery_sends a LEFT JOIN recovery_usage_slots s USING(attempt_id) "
                "LEFT JOIN recovery_producers p ON p.producer_id=a.producer_id "
                "WHERE a.run_id=? AND a.sequence=?",
                (member.run_id, candidate_sequence),
            ).fetchone()
            if (
                meta is None
                or len(result) >= _MAX_SOURCE_ROWS
                or meta[0] != sequence + 1
                or meta[3] != meta[6]
                or meta[1] != meta[7]
                or (meta[13], meta[14], meta[15], meta[16])
                != (member.run_id, "sdk", "closed", current_incarnation())
                or any(
                    type(item) is not str or not item or len(item) > 255
                    for item in meta[1:4]
                )
            ):
                raise RecoveryRefused("send_inventory_invalid")
            sequence = meta[0]
            payload: bytes | None = None
            if meta[4] == "accounted":
                if (
                    meta[8] != "committed"
                    or meta[12] != "blob"
                    or type(meta[11]) is not int
                    or not 0 < meta[11] <= 65_536
                    or type(meta[9]) is not int
                    or meta[9] <= 0
                ):
                    raise RecoveryRefused("invalid_retained_usage_payload")
                raw = conn.execute(
                    "SELECT payload_json FROM recovery_usage_slots WHERE delta_id=? "
                    "AND typeof(payload_json)='blob' AND length(payload_json)=?",
                    (meta[3], meta[11]),
                ).fetchone()
                if raw is None:
                    raise RecoveryRefused("invalid_retained_usage_payload")
                payload = bytes(raw[0])
            elif (
                meta[4] != "no_charge_proved"
                or meta[5] != "sdk_not_entered"
                or meta[8] != "no_charge"
                or meta[9] is not None
                or meta[10] is not None
                or meta[12] != "null"
            ):
                raise RecoveryRefused("unknown_send_outcome")
            value = {
                "schema": VALUE_SCHEMA,
                "record": "send",
                "attempt_id": meta[1],
                "run_id": member.run_id,
                "producer_id": meta[2],
                "sequence": sequence,
                "state": meta[4],
                "delta_id": meta[3],
                "reason": meta[5],
                "slot_state": meta[8],
                "slot_attempt_id": meta[7],
                "slot_delta_id": meta[6],
                "ack_revision": meta[9],
                "payload_sha256": meta[10],
                "payload_base64": base64.b64encode(payload).decode("ascii")
                if payload
                else None,
            }
            try:
                validate_artifact_value("send_ledger", value)
            except ValueError as exc:
                raise RecoveryRefused("send_inventory_invalid") from exc
            result.append(value)
            budget.charge_value("send_ledger", value)
    return result


def _provider_values(
    conn: sqlite3.Connection,
    scope: RecoveryScope,
    evidence: PreparedProviderEvidence,
    budget: _Budget,
) -> list[dict[str, object]]:
    retained = read_admission(conn, scope.session_id)
    if retained.canonical_bytes() != evidence.admission.canonical_bytes():
        raise RecoveryRefused("provider_admission_mismatch")
    values: list[dict[str, object]] = []
    count = conn.execute(
        "SELECT COUNT(*) FROM recovery_provider_invocations WHERE session_id=?",
        (scope.session_id,),
    ).fetchone()[0]
    if type(count) is not int or not 0 <= count <= 16_384:
        raise RecoveryRefused("provider_inventory_invalid")
    iterator = iter(iter_provider_rows(conn, scope))
    for sequence in range(count):
        budget.check()
        lengths = conn.execute(
            "SELECT "
            + ",".join(
                f"length(substr(CAST({name} AS BLOB),1,257))"
                for name in (
                    "invocation_id",
                    "session_id",
                    "run_id",
                    "producer_id",
                    "create_invocation_id",
                    "container_id",
                    "container_attestation_sha256",
                    "outcome_reason",
                )
            )
            + " FROM recovery_provider_invocations WHERE session_id=? AND sequence=?",
            (scope.session_id, sequence),
        ).fetchone()
        if lengths is None or any(
            size is not None and (type(size) is not int or size > 255)
            for size in lengths
        ):
            raise RecoveryRefused("provider_inventory_invalid")
        budget.preview_source(
            sum(size or 0 for size in lengths), "provider_invocations"
        )
        try:
            row = next(iterator)
        except StopIteration as exc:
            raise RecoveryRefused("provider_inventory_invalid") from exc
        if row.state != "returned":
            raise RecoveryRefused("provider_inventory_invalid")
        owner = conn.execute(
            "SELECT run_id,kind,state,owner_incarnation FROM recovery_producers "
            "WHERE producer_id=?",
            (row.producer_id,),
        ).fetchone()
        if (
            owner is None
            or owner[0] != row.run_id
            or owner[1] != "tool"
            or owner[2] != "closed"
            or owner[3] != current_incarnation()
        ):
            raise RecoveryRefused("provider_inventory_invalid")
        value = {
            "schema": VALUE_SCHEMA,
            "record": "invocation",
            **row.model_dump(mode="json"),
        }
        try:
            validate_artifact_value("provider_invocations", value)
        except ValueError as exc:
            raise RecoveryRefused("provider_inventory_invalid") from exc
        values.append(value)
        budget.charge_value("provider_invocations", value)
    if next(iterator, None) is not None:
        raise RecoveryRefused("provider_inventory_invalid")
    if evidence.state == "unused":
        if (
            values
            or evidence.container_id is not None
            or evidence.container_attestation_sha256 is not None
        ):
            raise RecoveryRefused("provider_inventory_invalid")
    elif (
        not values
        or values[0]["kind"] != "create_environment"
        or values[0]["container_id"] != evidence.container_id
        or values[0]["container_attestation_sha256"]
        != evidence.container_attestation_sha256
    ):
        raise RecoveryRefused("provider_inventory_invalid")
    return values


def _cells_row(
    value: dict[str, object], columns: tuple[tuple[str, str, int], ...]
) -> dict[str, object]:
    cells = value["cells"]
    decoded = decode_sqlite_cells(cells)
    return dict(zip((name for name, _, _ in columns), decoded, strict=True))


def _artifact_rows(
    kind: ArtifactKind, values: list[dict[str, object]]
) -> tuple[ArtifactRow, ...]:
    rows = []
    for index, value in enumerate(values):
        validate_artifact_value(kind, value)
        rows.append(
            ArtifactRow(
                row_index=index,
                kind=kind,
                value=cast(dict[str, JsonValue], value),
                row_sha256=document_sha256(
                    f"hermes.recovery.row/{kind}/v1",
                    {"row_index": index, "kind": kind, "value": value},
                ),
            )
        )
    return tuple(rows)


def _data_bodies(
    sections: dict[ArtifactKind, tuple[ArtifactRow, ...]], budget: _Budget
) -> list[DataBody]:
    bodies: list[DataBody] = []
    for kind in _KINDS:
        section = sections[kind]
        limit = 64 if kind == "transcript" else 1024
        current: list[ArtifactRow] = []
        first = 0
        for row in section:
            budget.check()
            candidate = (*current, row)

            def fits(items: tuple[ArtifactRow, ...]) -> bool:
                try:
                    body = DataBody(
                        data_index=len(bodies),
                        kind=kind,
                        first_row_index=first,
                        rows=items,
                    )
                    probe = DataArtifactPage(
                        schema="hermes.recovery-page/v1",
                        receipt_sha256="0" * 64,
                        route_page=MAX_ROUTE_PAGES - 1,
                        body=body,
                        next_page=MAX_ROUTE_PAGES - 1,
                    )
                    bounded_response_bytes(probe)
                    return True
                except ValueError:
                    return False

            if len(candidate) > limit or not fits(candidate):
                if not current:
                    raise RecoveryRefused("snapshot_row_oversized")
                bodies.append(
                    DataBody(
                        data_index=len(bodies),
                        kind=kind,
                        first_row_index=first,
                        rows=tuple(current),
                    )
                )
                first += len(current)
                current = [row]
                if not fits((row,)):
                    raise RecoveryRefused("snapshot_row_oversized")
            else:
                current.append(row)
            if len(bodies) >= MAX_ROUTE_PAGES:
                raise RecoveryRefused("snapshot_page_limit")
        if current:
            bodies.append(
                DataBody(
                    data_index=len(bodies),
                    kind=kind,
                    first_row_index=first,
                    rows=tuple(current),
                )
            )
        if len(bodies) >= MAX_ROUTE_PAGES:
            raise RecoveryRefused("snapshot_page_limit")
    return bodies


def _manifest_groups(
    header: ManifestHeader, descriptors: list[PageDescriptor], budget: _Budget
) -> list[tuple[PageDescriptor, ...]]:
    groups: list[tuple[PageDescriptor, ...]] = []
    current: list[PageDescriptor] = []
    for descriptor in descriptors:
        budget.check()
        candidate = (*current, descriptor)

        def fits(items: tuple[PageDescriptor, ...]) -> bool:
            try:
                probe = ManifestArtifactPage(
                    schema="hermes.recovery-page/v1",
                    receipt_sha256="0" * 64,
                    route_page=len(groups),
                    manifest_index=len(groups),
                    header=header if not groups else None,
                    descriptors=items,
                    next_page=MAX_ROUTE_PAGES - 1,
                )
                bounded_response_bytes(probe)
                return True
            except ValueError:
                return False

        if len(candidate) > 1024 or not fits(candidate):
            if not current:
                raise RecoveryRefused("snapshot_manifest_oversized")
            groups.append(tuple(current))
            current = [descriptor]
            if not fits((descriptor,)):
                raise RecoveryRefused("snapshot_manifest_oversized")
        else:
            current.append(descriptor)
        if len(groups) + len(descriptors) >= MAX_ROUTE_PAGES * 2:
            raise RecoveryRefused("snapshot_page_limit")
    groups.append(tuple(current))
    if len(groups) + len(descriptors) > MAX_ROUTE_PAGES:
        raise RecoveryRefused("snapshot_page_limit")
    return groups


def _provider_binding(
    evidence: PreparedProviderEvidence, invocation_rows: tuple[ArtifactRow, ...]
) -> ProviderBinding:
    admission = evidence.admission
    root = hash_rows("provider_invocations", invocation_rows)
    value = {
        "provider": admission.provider,
        "state": evidence.state,
        "session_id": admission.session_id,
        "hermes_revision": admission.hermes_revision,
        "source_sha256": admission.source_sha256,
        "provider_sha256": admission.provider_sha256,
        "reference": admission.reference.model_dump(mode="json"),
        "status_state": evidence.signed_status.status.state,
        "status_revision": evidence.signed_status.status.revision,
        "signed_status": evidence.signed_status.model_dump(mode="json", by_alias=True),
        "signed_status_sha256": evidence.signed_status_sha256,
        "container_id": evidence.container_id,
        "container_attestation_sha256": evidence.container_attestation_sha256,
        "invocation_count": len(invocation_rows),
        "invocations_sha256": root.sha256,
    }
    value["binding_sha256"] = document_sha256(
        "hermes.recovery.provider-binding/v1", value
    )
    return ProviderBinding.model_validate(value)


def _assemble(
    store: RecoveryStore,
    scope: RecoveryScope,
    request: SealRequest,
    members: tuple[RecoveryMember, ...],
    revision: int,
    evidence: PreparedProviderEvidence,
    values: dict[str, list[dict[str, object]]],
    usage: dict[str, object],
    budget: _Budget,
) -> tuple[SealResult, bytes, bytes, tuple[bytes, ...]]:
    sections = {kind: _artifact_rows(kind, values[kind]) for kind in _KINDS}
    roots = {
        kind: hash_rows(
            kind,
            sections[kind],
            max_rows=MAX_TRANSCRIPT_ROWS if kind == "transcript" else None,
        )
        for kind in _KINDS
    }
    if roots["accounting"].byte_count > MAX_ACCOUNTING_BYTES:
        raise RecoveryRefused("accounting_oversized")
    bodies = _data_bodies(sections, budget)
    descriptors = [descriptor_for_body(body) for body in bodies]
    header = ManifestHeader(
        data_page_count=len(bodies),
        transcript_row_count=len(sections["transcript"]),
        accounting_row_count=len(sections["accounting"]),
        send_row_count=len(sections["send_ledger"]),
        provider_invocation_row_count=len(sections["provider_invocations"]),
    )
    groups = _manifest_groups(header, descriptors, budget)
    manifest = manifest_sha256(header, descriptors)
    snapshot_bytes = manifest.byte_count + sum(
        root.byte_count for root in roots.values()
    )
    if (
        snapshot_bytes > MAX_SNAPSHOT_BYTES
        or len(groups) + len(bodies) > MAX_ROUTE_PAGES
    ):
        raise RecoveryRefused("snapshot_oversized")
    provider = _provider_binding(evidence, sections["provider_invocations"])
    try:
        acknowledged = AcknowledgedUsage.model_validate(usage)
        receipt = SealReceipt(
            schema="hermes.recovery-receipt/v1",
            store_id=store.store_id,
            gateway_incarnation=current_incarnation(),
            profile=scope.profile,
            scope_digest=scope.scope_digest,
            session_id=scope.session_id,
            members=members,
            sealed_at=time.time(),
            revision=revision + 1,
            membership_sha256=request.expected_membership_sha256,
            transcript_sha256=roots["transcript"].sha256,
            snapshot_manifest_sha256=manifest.sha256,
            accounting_sha256=roots["accounting"].sha256,
            send_ledger_sha256=roots["send_ledger"].sha256,
            manifest_page_count=len(groups),
            data_page_count=len(bodies),
            transcript_row_count=len(sections["transcript"]),
            accounting_row_count=len(sections["accounting"]),
            send_row_count=len(sections["send_ledger"]),
            provider_invocation_row_count=len(sections["provider_invocations"]),
            snapshot_bytes=snapshot_bytes,
            acknowledged_usage=acknowledged,
            provider_binding=provider,
            no_calls=not values["send_ledger"],
        )
        result = SealResult(
            schema="hermes.recovery/v1",
            state="sealed",
            request_id=request.request_id,
            reasons=(),
            receipt=receipt,
        )
    except ValueError as exc:
        raise RecoveryRefused("seal_receipt_invalid") from exc
    receipt_hash = receipt_sha256(receipt)
    pages = []
    total_pages = len(groups) + len(bodies)
    for index, group in enumerate(groups):
        budget.check()
        page = ManifestArtifactPage(
            schema="hermes.recovery-page/v1",
            receipt_sha256=receipt_hash,
            route_page=index,
            manifest_index=index,
            header=header if index == 0 else None,
            descriptors=group,
            next_page=index + 1 if index + 1 < total_pages else None,
        )
        pages.append(page)
    for index, body in enumerate(bodies):
        budget.check()
        route_page = len(groups) + index
        pages.append(
            DataArtifactPage(
                schema="hermes.recovery-page/v1",
                receipt_sha256=receipt_hash,
                route_page=route_page,
                body=body,
                next_page=route_page + 1 if route_page + 1 < total_pages else None,
            )
        )
    verify_sealed_pages(receipt, pages)
    encoded_pages = tuple(bounded_response_bytes(page) for page in pages)
    result_bytes = bounded_response_bytes(result)
    receipt_bytes = canonical_json_bytes(receipt)
    if (
        len(receipt_bytes) > MAX_ACCOUNTING_BYTES
        or sum(map(len, encoded_pages)) > MAX_SNAPSHOT_BYTES
    ):
        raise RecoveryRefused("snapshot_oversized")
    return result, result_bytes, receipt_bytes, encoded_pages


def finalize(
    store: RecoveryStore,
    scope: RecoveryScope,
    request: SealRequest,
    evidence: PreparedProviderEvidence | None,
    *,
    deadline: float | None = None,
) -> SealResult:
    """Commit one complete proof, or refuse with the close barrier still durable.

    `begin_close` is a separate, previously committed barrier. A committed
    identical seal can be read without a predecessor producer or fresh provider
    readback. An unsealed session always requires the live selected capture.
    """
    store._check_scope(scope)
    if request.session_id != scope.session_id:
        raise RecoveryRefused("scope_mismatch")
    budget = _Budget(deadline)
    budget.check()
    committed = _read_document(store, scope, request.run_ids[0], request=request)
    if committed is not None:
        return committed[0]
    if (
        type(evidence) is not PreparedProviderEvidence
        or evidence._issuer is not _EVIDENCE_ISSUER
        or _PREPARED.get(id(evidence)) is not evidence
    ):
        raise RecoveryRefused("provider_readback_unavailable")
    if evidence.admission.session_id != scope.session_id:
        raise RecoveryRefused("provider_admission_mismatch")
    evidence.capture.require_selected()

    def _tx(conn: sqlite3.Connection) -> SealResult:
        budget.start()
        conn.set_progress_handler(budget.progress, 1000)
        try:
            existing = conn.execute(
                "SELECT result_json FROM recovery_seal_documents WHERE session_id=?",
                (scope.session_id,),
            ).fetchone()
            if existing is not None:
                # A concurrent identical finalizer won the commit. Reparse the
                # committed bytes; never recompute a second receipt.
                document = _read_document_on_conn(
                    conn, scope, request.run_ids[0], request
                )
                return document[0]
            from hermes_state_recovery_exclusions import _catalog

            if _catalog(conn) != "full":
                raise RecoveryRefused("protected_session_authority_unavailable")
            revision, members = _member_preflight(conn, store, scope, request, budget)
            acks, lineage = _ack_values(conn, scope, budget)
            transcript, accounting = _source_values(conn, scope, budget, lineage)
            if _cells_row(accounting[0], SESSION_COLUMNS)["source"] != "api_server":
                raise RecoveryRefused("source_session_mismatch")
            accounting.extend(acks)
            sends = _send_values(conn, scope, members, budget)
            invocations = _provider_values(conn, scope, evidence, budget)
            values = {
                "transcript": transcript,
                "accounting": accounting,
                "send_ledger": sends,
                "provider_invocations": invocations,
            }
            try:
                semantic_check = verify_artifact_crosslinks(
                    values,
                    SemanticContext(
                        session_id=scope.session_id,
                        members=tuple(
                            (member.run_id, member.generation) for member in members
                        ),
                        provider_container_id=evidence.container_id,
                        provider_attestation_sha256=evidence.container_attestation_sha256,
                        no_calls=not sends,
                    ),
                )
            except ValueError as exc:
                raise RecoveryRefused("snapshot_semantics_invalid") from exc
            if (
                semantic_check.complete_source_proof
                or not semantic_check.route_replay_complete
            ):
                raise RecoveryRefused("snapshot_semantics_invalid")
            usage = semantic_check.acknowledged_usage.model_dump(
                exclude={"pricing_version"}
            )
            result, result_bytes, receipt_bytes, page_bytes = _assemble(
                store,
                scope,
                request,
                members,
                revision,
                evidence,
                values,
                usage,
                budget,
            )
            if result.receipt is None:
                raise RecoveryRefused("seal_receipt_invalid")
            receipt_hash = receipt_sha256(result.receipt)
            evidence.capture.require_selected()
            # Documents are inserted first to satisfy the pages' strict FK and
            # insert guard. Every insert, the tombstone and result roll back as one.
            conn.execute(
                "INSERT INTO recovery_seal_documents"
                "(session_id,result_json,receipt_json,receipt_sha256,page_count) "
                "VALUES(?,?,?,?,?)",
                (
                    scope.session_id,
                    result_bytes,
                    receipt_bytes,
                    receipt_hash,
                    len(page_bytes),
                ),
            )
            for index, page in enumerate(page_bytes):
                budget.check()
                conn.execute(
                    "INSERT INTO recovery_sealed_pages(session_id,route_page,page_bytes) "
                    "VALUES(?,?,?)",
                    (scope.session_id, index, page),
                )
            changed = conn.execute(
                "UPDATE recovery_sessions SET phase='sealed',revision=revision+1,receipt_json=? "
                "WHERE session_id=? AND phase='closing' AND revision=? AND receipt_json IS NULL",
                (receipt_bytes.decode("utf-8"), scope.session_id, revision),
            ).rowcount
            if changed != 1:
                raise RecoveryRefused("close_conflict")
            budget.check()
            return result
        except sqlite3.OperationalError as exc:
            try:
                budget.check()
            except RecoveryRefused as deadline_exc:
                raise deadline_exc from exc
            raise
        finally:
            conn.set_progress_handler(None, 0)

    return store._write(_tx, patience_s=1.0)


def _read_document_on_conn(
    conn: sqlite3.Connection,
    scope: RecoveryScope,
    root_id: str,
    request: SealRequest | None = None,
) -> tuple[SealResult, bytes, SealReceipt, int]:
    metadata = conn.execute(
        "SELECT s.phase,typeof(s.close_request_json),"
        "length(substr(CAST(s.close_request_json AS BLOB),1,?)),"
        "typeof(s.receipt_json),length(substr(CAST(s.receipt_json AS BLOB),1,?)),"
        "typeof(d.result_json),length(d.result_json),"
        "typeof(d.receipt_json),length(d.receipt_json),"
        "typeof(d.receipt_sha256),"
        "length(substr(CAST(d.receipt_sha256 AS BLOB),1,65)),d.page_count "
        "FROM recovery_sessions s JOIN recovery_seal_documents d USING(session_id) "
        "WHERE s.session_id=? AND s.profile=? AND s.scope_digest=? AND s.root_run_id=?",
        (
            MAX_RESPONSE_BYTES + 1,
            MAX_ACCOUNTING_BYTES + 1,
            scope.session_id,
            scope.profile,
            scope.scope_digest,
            root_id,
        ),
    ).fetchone()
    if metadata is None or metadata[0] != "sealed":
        raise RecoveryRefused("seal_not_found")
    if (
        metadata[1] != "text"
        or type(metadata[2]) is not int
        or not 0 < metadata[2] <= MAX_RESPONSE_BYTES
        or metadata[3] != "text"
        or type(metadata[4]) is not int
        or not 0 < metadata[4] <= MAX_ACCOUNTING_BYTES
        or metadata[5] != "blob"
        or type(metadata[6]) is not int
        or not 0 < metadata[6] <= MAX_RESPONSE_BYTES
        or metadata[7] != "blob"
        or type(metadata[8]) is not int
        or not 0 < metadata[8] <= MAX_ACCOUNTING_BYTES
        or metadata[9] != "text"
        or metadata[10] != 64
        or type(metadata[11]) is not int
        or not 1 <= metadata[11] <= MAX_ROUTE_PAGES
    ):
        raise RecoveryRefused("sealed_document_invalid")
    row = conn.execute(
        "SELECT s.close_request_json,s.receipt_json,d.result_json,d.receipt_json,"
        "d.receipt_sha256,d.page_count "
        "FROM recovery_sessions s JOIN recovery_seal_documents d USING(session_id) "
        "WHERE s.session_id=? AND s.profile=? AND s.scope_digest=? AND s.root_run_id=?",
        (scope.session_id, scope.profile, scope.scope_digest, root_id),
    ).fetchone()
    try:
        if (
            row is None
            or type(row[0]) is not str
            or type(row[1]) is not str
            or type(row[2]) is not bytes
            or type(row[3]) is not bytes
            or type(row[4]) is not str
            or row[5] != metadata[11]
            or len(row[0].encode("utf-8")) != metadata[2]
            or len(row[1].encode("utf-8")) != metadata[4]
            or len(row[2]) != metadata[6]
            or len(row[3]) != metadata[8]
        ):
            raise RecoveryRefused("sealed_document_invalid")
    except UnicodeError as exc:
        raise RecoveryRefused("sealed_document_invalid") from exc
    if request is not None and row[0] != request.model_dump_json():
        raise RecoveryRefused("close_conflict")
    try:
        result = SealResult.model_validate(strict_json_loads(row[2]))
        receipt = SealReceipt.model_validate(
            strict_json_loads(row[3], max_bytes=MAX_ACCOUNTING_BYTES)
        )
        if (
            result.state != "sealed"
            or result.receipt != receipt
            or (request is not None and result.request_id != request.request_id)
            or canonical_json_bytes(result) != row[2]
            or canonical_json_bytes(receipt) != row[3]
            or receipt_sha256(receipt) != row[4]
            or row[1] != row[3].decode("utf-8")
            or receipt.session_id != scope.session_id
            or receipt.store_id != scope.store_id
            or receipt.profile != scope.profile
            or receipt.scope_digest != scope.scope_digest
            or receipt.members[0].run_id != root_id
            or receipt.manifest_page_count + receipt.data_page_count != row[5]
        ):
            raise ValueError("sealed document mismatch")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise RecoveryRefused("sealed_document_invalid") from exc
    return result, row[2], receipt, row[5]


def _read_document(
    store: RecoveryStore,
    scope: RecoveryScope,
    root_id: str,
    request: SealRequest | None = None,
) -> tuple[SealResult, bytes, SealReceipt, int] | None:
    store._check_scope(scope)

    def _read(conn: sqlite3.Connection):
        conn.execute("BEGIN")
        try:
            exists = conn.execute(
                "SELECT 1 FROM recovery_seal_documents WHERE session_id=?",
                (scope.session_id,),
            ).fetchone()
            if exists is None:
                conn.execute("COMMIT")
                return None
            result = _read_document_on_conn(conn, scope, root_id, request)
            conn.execute("COMMIT")
            return result
        except BaseException:
            conn.rollback()
            raise

    return store.db._read_retrying_ioerr(_read)


def read_seal_bytes(store: RecoveryStore, scope: RecoveryScope, root_id: str) -> bytes:
    document = _read_document(store, scope, root_id)
    if document is None:
        raise RecoveryRefused("seal_not_found")
    return document[1]


def read_sealed_page_bytes(
    store: RecoveryStore, scope: RecoveryScope, root_id: str, page: int
) -> bytes:
    """Return one saved page after verifying the complete immutable page set."""
    from pydantic import TypeAdapter
    from gateway.platforms.api_server_recovery_contract import SealedArtifactPage

    if type(page) is not int or page < 0 or page >= MAX_ROUTE_PAGES:
        raise RecoveryRefused("sealed_page_not_found")
    store._check_scope(scope)

    def _read(conn: sqlite3.Connection) -> bytes:
        conn.execute("BEGIN")
        try:
            _, _, receipt, count = _read_document_on_conn(conn, scope, root_id)
            if page >= count:
                raise RecoveryRefused("sealed_page_not_found")
            encoded: list[bytes] = []
            parsed = []
            adapter = TypeAdapter(SealedArtifactPage)
            encoded_total = 0
            if (
                conn.execute(
                    "SELECT 1 FROM recovery_sealed_pages WHERE session_id=? "
                    "AND route_page>=? LIMIT 1",
                    (scope.session_id, count),
                ).fetchone()
                is not None
            ):
                raise RecoveryRefused("sealed_page_invalid")
            for index in range(count):
                meta = conn.execute(
                    "SELECT length(page_bytes),typeof(page_bytes) FROM recovery_sealed_pages "
                    "WHERE session_id=? AND route_page=?",
                    (scope.session_id, index),
                ).fetchone()
                if (
                    meta is None
                    or meta[1] != "blob"
                    or type(meta[0]) is not int
                    or not 0 < meta[0] <= MAX_RESPONSE_BYTES
                ):
                    raise RecoveryRefused("sealed_page_invalid")
                row = conn.execute(
                    "SELECT page_bytes FROM recovery_sealed_pages "
                    "WHERE session_id=? AND route_page=?",
                    (scope.session_id, index),
                ).fetchone()
                raw = bytes(row[0])
                try:
                    parsed_page = adapter.validate_python(strict_json_loads(raw))
                    if canonical_json_bytes(parsed_page) != raw:
                        raise ValueError("noncanonical page")
                except (TypeError, ValueError, UnicodeError) as exc:
                    raise RecoveryRefused("sealed_page_invalid") from exc
                encoded.append(raw)
                parsed.append(parsed_page)
                encoded_total += len(raw)
                if encoded_total > MAX_SNAPSHOT_BYTES:
                    raise RecoveryRefused("sealed_page_invalid")
            try:
                verify_sealed_pages(receipt, parsed)
            except ValueError as exc:
                raise RecoveryRefused("sealed_page_invalid") from exc
            conn.execute("COMMIT")
            return encoded[page]
        except BaseException:
            conn.rollback()
            raise

    return store.db._read_retrying_ioerr(_read)
