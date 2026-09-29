"""Pure sealed-value framing from actual SQLite storage classes."""

from __future__ import annotations

import sqlite3
import struct
import json
from pathlib import Path
from copy import deepcopy
import re

import pytest

from hermes_state_recovery_values import (
    MESSAGE_COLUMNS,
    MODEL_USAGE_COLUMNS,
    SESSION_COLUMNS,
    decode_sqlite_cells,
    encode_sqlite_cells,
    validate_artifact_value,
    SemanticContext,
    verify_artifact_crosslinks,
)


def test_exact_column_inventory_matches_live_sqlite():
    from hermes_state_common import SCHEMA_SQL

    # Execute the three actual source declarations without SessionDB's unrelated
    # writable bootstrap, whose exclusion claims are separately tested.
    with sqlite3.connect(":memory:") as conn:
        for table, expected in (
            ("sessions", SESSION_COLUMNS),
            ("messages", MESSAGE_COLUMNS),
            ("session_model_usage", MODEL_USAGE_COLUMNS),
        ):
            match = re.search(
                rf"CREATE TABLE IF NOT EXISTS {table} \(.*?\n\);", SCHEMA_SQL, re.DOTALL
            )
            assert match is not None
            conn.executescript(match.group())
            actual = tuple(
                (row[1], row[2], row[5])
                for row in conn.execute(f"PRAGMA table_info({table})")
            )
            assert actual == expected
    assert tuple(map(len, (SESSION_COLUMNS, MESSAGE_COLUMNS, MODEL_USAGE_COLUMNS))) == (
        58,
        26,
        18,
    )


def test_sqlite_cell_storage_classes_are_bit_exact():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE sample (n, i, f, text_value, unicode_value, blob_value)")
    conn.execute(
        "INSERT INTO sample VALUES (?,?,?,?,?,?)",
        (None, -(2**63), -0.0, '{"looks":"json"}', "Café ✓", b"\x00\x01\xff"),
    )
    row = conn.execute("SELECT * FROM sample").fetchone()
    storage = conn.execute(
        "SELECT typeof(n),typeof(i),typeof(f),typeof(text_value),"
        "typeof(unicode_value),typeof(blob_value) FROM sample"
    ).fetchone()
    cells = encode_sqlite_cells(row, storage)
    assert cells == [
        ["n"],
        ["i", str(-(2**63))],
        ["f", "8000000000000000"],
        ["s", '{"looks":"json"}'],
        ["s", "Café ✓"],
        ["b", "AAH/"],
    ]
    decoded = decode_sqlite_cells(cells)
    assert decoded[:2] == (None, -(2**63))
    assert struct.pack(">d", decoded[2]) == struct.pack(">d", -0.0)
    assert decoded[3:] == ('{"looks":"json"}', "Café ✓", b"\x00\x01\xff")


@pytest.mark.parametrize(
    "bad",
    [
        [["i", "01"]],
        [["i", "-0"]],
        [["i", str(2**63)]],
        [["f", "7ff0000000000000"]],
        [["f", "800000000000000A"]],
        [["b", "AAH_"]],
        [["b", "AAH/"], ["n", "extra"]],
        [["x", "a"]],
        [["s", "\ud800"]],
    ],
)
def test_bad_cells_refuse(bad):
    with pytest.raises(ValueError):
        decode_sqlite_cells(bad)


def test_closed_record_keys_and_fixed_vector():
    cells = [["n"] for _ in MESSAGE_COLUMNS]
    cells[0] = ["i", "1"]
    cells[1] = ["s", "session"]
    value = {
        "schema": "hermes.recovery.artifact-value/v1",
        "record": "message",
        "cells": cells,
        "lineage": [{"write_id": "w", "position": 0}],
    }
    assert validate_artifact_value("transcript", value).record == "message"
    with pytest.raises(ValueError):
        validate_artifact_value("accounting", value)
    with pytest.raises(ValueError):
        validate_artifact_value("transcript", {**value, "extra": 1})
    with pytest.raises(ValueError):
        validate_artifact_value("transcript", {**value, "cells": cells[:-1]})


def test_shared_sqlite_origin_fixture_is_complete_and_lossless():
    fixture = json.loads(
        (
            Path(__file__).parents[1] / "fixtures" / "recovery_artifact_values_v1.json"
        ).read_text(encoding="utf-8")
    )
    for table, columns in (
        ("sessions", SESSION_COLUMNS),
        ("messages", MESSAGE_COLUMNS),
        ("session_model_usage", MODEL_USAGE_COLUMNS),
    ):
        source = fixture["tables"][table]
        assert source["columns"] == [list(column) for column in columns]
        cells = source["cells"]
        decoded = decode_sqlite_cells(cells)
        storage = tuple(
            {"n": "null", "i": "integer", "f": "real", "s": "text", "b": "blob"}[
                cell[0]
            ]
            for cell in cells
        )
        assert encode_sqlite_cells(decoded, storage) == cells
    assert fixture["scalar_cells"][2] == ["f", "8000000000000000"]


def test_fixture_ack_text_is_exact_guarded_writer_output(tmp_path):
    from agent.recovery_context import (
        current_incarnation,
        issue_producer_permit,
        issue_write_permit,
    )
    from gateway.platforms.api_server_recovery_contract import RecoveryAdmission
    from hermes_state import SessionDB
    from hermes_state_recovery import AdmissionIdentity, RecoveryScope, RecoveryStore
    from hermes_state_recovery_guard import guarded_write
    from hermes_state_recovery_message_result import (
        MessageOutcomeV1,
        MessageWriteResultV1,
    )
    from tests.recovery_provider_fixture import provider_admission

    fixture = json.loads(
        (
            Path(__file__).parents[1] / "fixtures" / "recovery_artifact_values_v1.json"
        ).read_text(encoding="utf-8")
    )
    expected = fixture["sections"]["accounting"][2]
    db = SessionDB(tmp_path / "state.db")
    try:
        store = RecoveryStore(db)
        scope = RecoveryScope(store.store_id, "factory", "b" * 64, "fixture-session")
        admitted = store.reserve(
            RecoveryAdmission(
                schema="hermes.recovery/v1", generation=0, parent_run_id=None
            ),
            AdmissionIdentity(
                scope,
                "byf-recovery-v1:one",
                "a" * 64,
                "root",
                current_incarnation(),
                provider_admission(scope.session_id),
            ),
        )
        assert admitted.outcome == "created"
        producer = issue_producer_permit(store, admitted.handoff)
        writer = issue_write_permit(producer, store, scope, "root", 0)
        result = MessageWriteResultV1((MessageOutcomeV1("inserted", None, 7),))
        guarded_write(
            db,
            writer,
            "message",
            expected["write_id"],
            expected["payload_sha256"],
            lambda _conn: result.to_ack_value(),
        )
        row = db._read_one(
            "SELECT result_json FROM recovery_write_acks WHERE write_id=?",
            (expected["write_id"],),
        )
        assert row is not None
        assert row[0] == expected["result_json"]
    finally:
        db.close()


def test_included_semantic_crosslinks_are_bounded_and_explicitly_partial():
    fixture = json.loads(
        (
            Path(__file__).parents[1] / "fixtures" / "recovery_artifact_values_v1.json"
        ).read_text(encoding="utf-8")
    )
    context = SemanticContext(**{**fixture["context"], "members": (("root", 0),)})
    summary = verify_artifact_crosslinks(fixture["sections"], context)
    assert (
        summary.message_count,
        summary.write_ack_count,
        summary.send_count,
        summary.invocation_count,
        summary.accounted_api_calls,
    ) == (1, 1, 1, 2, 1)
    assert summary.actual_cost_usd is None
    assert summary.complete_source_proof is False
    assert summary.route_replay_complete is False

    for mutate in (
        lambda sections: sections["transcript"][0]["lineage"].clear(),
        lambda sections: sections["accounting"][2].update(ack_revision=2),
        lambda sections: sections["accounting"][2].update(
            result_json=sections["accounting"][2]["result_json"]
            .replace(": ", ":")
            .replace(", ", ",")
        ),
        lambda sections: sections["send_ledger"][0].update(slot_attempt_id="other"),
        lambda sections: sections["provider_invocations"][1].update(
            create_invocation_id="other"
        ),
        lambda sections: sections["accounting"][0]["cells"][20].__setitem__(1, "9"),
    ):
        changed = deepcopy(fixture["sections"])
        mutate(changed)
        with pytest.raises(ValueError):
            verify_artifact_crosslinks(changed, context)


def test_unused_provider_and_no_calls_have_empty_independent_ledgers():
    fixture = json.loads(
        (
            Path(__file__).parents[1] / "fixtures" / "recovery_artifact_values_v1.json"
        ).read_text(encoding="utf-8")
    )
    sections = deepcopy(fixture["sections"])
    sections["send_ledger"] = []
    sections["provider_invocations"] = []
    sections["accounting"].pop(1)  # No per-model row without an accounted send.
    names = [name for name, _, _ in SESSION_COLUMNS]
    cells = sections["accounting"][0]["cells"]
    for name in (
        "api_call_count",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "reasoning_tokens",
    ):
        cells[names.index(name)] = ["i", "0"]
    cells[names.index("estimated_cost_usd")] = ["n"]
    context = SemanticContext(
        session_id="fixture-session",
        members=(("root", 0),),
        provider_container_id=None,
        provider_attestation_sha256=None,
        no_calls=True,
    )
    result = verify_artifact_crosslinks(sections, context)
    assert (
        result.send_count == result.invocation_count == result.accounted_api_calls == 0
    )
    with pytest.raises(ValueError):
        verify_artifact_crosslinks(
            sections, context.model_copy(update={"no_calls": False})
        )
