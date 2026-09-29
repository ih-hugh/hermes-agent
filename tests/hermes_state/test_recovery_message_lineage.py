"""Exact SQLite message provenance for protected batch acknowledgements."""

from __future__ import annotations

import pytest

from agent.recovery_context import bind_write_permit, issue_producer_permit, issue_write_permit
from hermes_state_recovery import RecoveryRefused
from hermes_state_recovery_message_result import (
    MAX_MESSAGE_RESULT_BYTES, prepare_message_batch, read_message_result,
)
from tests.hermes_state.test_recovery_write_guard import _protected_db


def _writer(tmp_path):
    db, store, scope, handoff = _protected_db(tmp_path)
    producer = issue_producer_permit(store, handoff)
    writer = issue_write_permit(producer, store, scope, "root", 0)
    with bind_write_permit(writer):
        db.create_session(scope.session_id, "api_server")
    return db, scope, writer


def _append(db, scope, writer, write_id, rows):
    return db.append_messages_batch(
        scope.session_id, rows, recovery_permit=writer, recovery_write_id=write_id,
        recovery_payload_sha256=prepare_message_batch(rows).payload_sha256,
    )


def _result(db, write_id):
    raw = db._read_one("SELECT result_json FROM recovery_write_acks WHERE write_id=?", (write_id,))[0]
    return read_message_result(raw)


def test_protected_insert_records_ordered_exact_ids_and_direct_retry(tmp_path):
    db, scope, writer = _writer(tmp_path)
    try:
        rows = [{"role": "user", "content": "same"}, {"role": "assistant", "content": "same"}]
        digest = prepare_message_batch(rows).payload_sha256
        assert _append(db, scope, writer, "lineage-1", rows) == 2
        result = _result(db, "lineage-1")
        assert [item.kind for item in result.outcomes] == ["inserted", "inserted"]
        assert [item.actual_message_id for item in result.outcomes] == [
            row["_row_id"] for row in rows]
        assert [item.requested_target_id for item in result.outcomes] == [None, None]
        assert db.append_messages_batch(
            scope.session_id, rows, recovery_permit=writer,
            recovery_write_id="lineage-1", recovery_payload_sha256=digest) == 2
        assert len(db.get_messages(scope.session_id)) == 2
        assert _append(db, scope, writer, "lineage-2", [
            {"role": "user", "content": "same"}, {"role": "assistant", "content": "same"}]) == 2
        assert len(db.get_messages(scope.session_id)) == 4
    finally:
        db.close()


def test_repair_and_adoption_record_original_target_and_actual_row(tmp_path):
    db, scope, writer = _writer(tmp_path)
    try:
        blank = {"role": "assistant", "content": "   "}
        assert _append(db, scope, writer, "blank", [blank]) == 1
        target = blank["_row_id"]
        repair = {"role": "assistant", "content": "repaired", "_row_id": target}
        assert _append(db, scope, writer, "repair", [repair]) == 0
        repaired = _result(db, "repair")
        assert [(o.kind, o.requested_target_id, o.actual_message_id)
                for o in repaired.outcomes] == [("repaired", target, target)]
        assert db.get_messages(scope.session_id)[0]["content"] == "repaired"
        proposal = {"role": "assistant", "content": "other", "_row_id": target}
        assert _append(db, scope, writer, "adopt", [proposal]) == 0
        adopted = _result(db, "adopt")
        assert [(o.kind, o.requested_target_id, o.actual_message_id)
                for o in adopted.outcomes] == [("adopted", target, target)]
        assert proposal["_canonical_content"] == "repaired"
    finally:
        db.close()


def test_changed_prepared_payload_or_digest_refuses_before_ack(tmp_path):
    db, scope, writer = _writer(tmp_path)
    try:
        rows = [{"role": "assistant", "content": "before", "_row_id": 7}]
        digest = prepare_message_batch(rows).payload_sha256
        rows[0]["content"] = "after"
        with pytest.raises(RecoveryRefused, match="write_payload_conflict"):
            db.append_messages_batch(scope.session_id, rows, recovery_permit=writer,
                                     recovery_write_id="forged", recovery_payload_sha256=digest)
        assert db._read_one("SELECT 1 FROM recovery_write_acks WHERE write_id='forged'") is None
    finally:
        db.close()


def test_failed_protected_callback_does_not_annotate_input_rows(tmp_path, monkeypatch):
    db, scope, writer = _writer(tmp_path)
    rows = [{"role": "user", "content": "rollback"}]
    original = dict(rows[0])
    monkeypatch.setattr(db, "_bump_session_counters", lambda *_args, **_kw: (_ for _ in ()).throw(
        RuntimeError("rollback after insert")))
    try:
        with pytest.raises(RuntimeError, match="rollback after insert"):
            _append(db, scope, writer, "rolled-back", rows)
        assert rows[0] == original
        assert db.get_messages(scope.session_id) == []
    finally:
        db.close()


@pytest.mark.parametrize("raw", [
    "1",
    '{"schema":"hermes.message-write-result/v1","schema":"duplicate"}',
    " " * (MAX_MESSAGE_RESULT_BYTES + 1),
])
def test_committed_retry_refuses_corrupt_or_oversized_raw_result(tmp_path, raw):
    db, scope, writer = _writer(tmp_path)
    try:
        original = [{"role": "user", "content": "durable"}]
        digest = prepare_message_batch(original).payload_sha256
        _append(db, scope, writer, "corrupted", [dict(original[0])])
        from hermes_state_recovery import RecoveryStore

        RecoveryStore(db)._write(lambda conn: conn.execute(
            "UPDATE recovery_write_acks SET result_json=? WHERE write_id='corrupted'", (raw,)))
        with pytest.raises(RecoveryRefused):
            db.append_messages_batch(
                scope.session_id, original, recovery_permit=writer,
                recovery_write_id="corrupted", recovery_payload_sha256=digest)
        assert len(db.get_messages(scope.session_id)) == 1
    finally:
        db.close()
