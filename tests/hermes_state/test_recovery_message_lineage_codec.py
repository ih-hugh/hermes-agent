"""Strict private preparation and result framing for protected message appends."""

from __future__ import annotations

import hashlib

import pytest

from hermes_state_recovery import RecoveryRefused
from hermes_state_recovery_message_result import (
    MAX_MESSAGE_BATCH_ROWS,
    MAX_MESSAGE_PREIMAGE_BYTES,
    MAX_MESSAGE_RESULT_BYTES,
    MessageOutcomeV1,
    MessageWriteResultV1,
    prepare_message_batch,
    read_message_result,
)


def test_prepared_batch_captures_exact_target_and_immutable_row_copy():
    rows = [{"role": "assistant", "content": ["before"], "_row_id": 7}]
    prepared = prepare_message_batch(rows)
    expected = prepared.payload_sha256
    rows[0]["content"][0] = "after"
    rows[0]["_row_id"] = 8
    fresh = prepared.fresh_rows()
    assert fresh == [{"role": "assistant", "content": ["before"], "_row_id": 7}]
    fresh[0]["content"][0] = "another"
    assert prepared.fresh_rows()[0]["content"] == ["before"]
    assert prepared.payload_sha256 == expected
    assert prepared.matches_input([{"role": "assistant", "content": ["before"], "_row_id": 7}])
    assert not prepared.matches_input(rows)
    assert prepared.payload_sha256 != prepare_message_batch(
        [{"role": "assistant", "content": ["before"], "_row_id": 8}]).payload_sha256
    assert expected == hashlib.sha256(prepared.canonical_bytes).hexdigest()


@pytest.mark.parametrize("rows", [
    [{"role": "assistant", "_row_id": True}],
    [{"role": "assistant", "_row_id": -1}],
    [{"role": "assistant", "_row_id": 2**63}],
    [{"role": "user", "content": float("nan")}],
])
def test_prepared_batch_refuses_invalid_semantics(rows):
    with pytest.raises(RecoveryRefused):
        prepare_message_batch(rows)


def test_prepared_batch_bounds_rows_and_bytes():
    with pytest.raises(RecoveryRefused):
        prepare_message_batch([{"role": "user"}] * (MAX_MESSAGE_BATCH_ROWS + 1))
    with pytest.raises(RecoveryRefused):
        prepare_message_batch([{"role": "user", "content": "x" * MAX_MESSAGE_PREIMAGE_BYTES}])


def test_result_records_ordered_insert_repair_adopt_and_strict_readback():
    result = MessageWriteResultV1((
        MessageOutcomeV1("inserted", None, 11),
        MessageOutcomeV1("repaired", 5, 12),
        MessageOutcomeV1("adopted", 7, 7),
    ))
    stored = result.to_ack_value()
    assert stored["inserted_count"] == 1
    assert read_message_result(stored) == result
    assert read_message_result(result.to_json()) == result


@pytest.mark.parametrize("raw", [
    '{"schema":"hermes.message-write-result/v1","schema":"hermes.message-write-result/v1"}',
    '{"schema":"hermes.message-write-result/v1","inserted_count":0,"outcomes":[],"extra":1}',
    '{"schema":"hermes.message-write-result/v1","inserted_count":true,"outcomes":[]}',
    '{"schema":"hermes.message-write-result/v1","inserted_count":0,"outcomes":[{"kind":"inserted","requested_target_id":null,"actual_message_id":1}]}',
    '{"schema":"hermes.message-write-result/v1","inserted_count":0,"outcomes":[{"kind":"adopted","requested_target_id":null,"actual_message_id":1}]}',
    '{"schema":"hermes.message-write-result/v1","inserted_count":0,"outcomes":[{"kind":[],"requested_target_id":1,"actual_message_id":1}]}',
    '1',
])
def test_result_refuses_duplicate_unknown_and_inconsistent_payload(raw):
    with pytest.raises(RecoveryRefused):
        read_message_result(raw)


def test_result_bounds_count_and_encoded_size():
    with pytest.raises(RecoveryRefused):
        MessageWriteResultV1(tuple(MessageOutcomeV1("inserted", None, i + 1)
                                   for i in range(MAX_MESSAGE_BATCH_ROWS + 1))).to_ack_value()
    with pytest.raises(RecoveryRefused):
        read_message_result(" " * (MAX_MESSAGE_RESULT_BYTES + 1))
