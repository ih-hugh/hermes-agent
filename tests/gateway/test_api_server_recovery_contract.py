"""Sealed recovery wire is independently reconstructible and byte bounded."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import hashlib
import json

import pytest

from gateway.platforms import api_server_recovery_contract as recovery_wire
from gateway.platforms.api_server_recovery_artifacts import (
    MAX_RESPONSE_BYTES,
    bounded_response_bytes,
    canonical_json_bytes,
    document_sha256,
    hash_rows,
    strict_json_loads,
)
from gateway.platforms.api_server_recovery_contract import (
    DataArtifactPage,
    DataBody,
    ManifestArtifactPage,
    ProviderBinding,
    SealReceipt,
    SealResult,
    receipt_sha256,
    verify_sealed_pages,
)


def _fixture() -> dict:
    return json.loads(
        (
            Path(__file__).parents[1] / "fixtures" / "recovery_contract_v1.json"
        ).read_text()
    )


def _pages(fixture: dict):
    return [ManifestArtifactPage.model_validate(fixture["sealed_pages"][0])] + [
        DataArtifactPage.model_validate(page) for page in fixture["sealed_pages"][1:]
    ]


def test_shared_fixture_pins_wire_schemas():
    for name, expected in _fixture()["schema_sha256"].items():
        model = getattr(recovery_wire, name)
        assert (
            hashlib.sha256(canonical_json_bytes(model.model_json_schema())).hexdigest()
            == expected
        )


def test_full_sealed_fixture_reconstructs_independent_roots():
    fixture = _fixture()
    receipt = SealReceipt.model_validate(fixture["seal_receipt"])
    assert (
        receipt.provider_binding.signed_status.status.schema_
        == "byf.workspace-status/v1"
    )
    assert receipt_sha256(receipt) == fixture["sealed_pages"][0]["receipt_sha256"]
    verify_sealed_pages(receipt, _pages(fixture))
    assert b"Caf\xc3\xa9 \xe2\x9c\x93" in canonical_json_bytes(fixture["sealed_pages"])


def test_complete_stream_rejects_trailing_none_page():
    fixture = _fixture()
    receipt = SealReceipt.model_validate(fixture["seal_receipt"])
    with pytest.raises(ValueError, match="unexpected extra page"):
        verify_sealed_pages(receipt, [*_pages(fixture), None])


def test_unused_provider_fixture_requires_empty_inventory_root():
    fixture = _fixture()
    receipt = SealReceipt.model_validate(fixture["unused_seal_receipt"])
    assert receipt.provider_binding.state == "unused"
    assert (
        receipt.provider_binding.invocations_sha256
        == hash_rows("provider_invocations", ()).sha256
    )
    pages = [ManifestArtifactPage.model_validate(fixture["unused_sealed_pages"][0])] + [
        DataArtifactPage.model_validate(page)
        for page in fixture["unused_sealed_pages"][1:]
    ]
    verify_sealed_pages(receipt, pages)


def test_root_and_nudge_fixture_keeps_ordered_lineage():
    fixture = _fixture()
    receipt = SealReceipt.model_validate(fixture["nudge_seal_receipt"])
    assert [member.generation for member in receipt.members] == [0, 1]
    pages = [ManifestArtifactPage.model_validate(fixture["nudge_sealed_pages"][0])] + [
        DataArtifactPage.model_validate(page)
        for page in fixture["nudge_sealed_pages"][1:]
    ]
    verify_sealed_pages(receipt, pages)


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "reordered",
        "descriptor",
        "missing_descriptor",
        "duplicate_descriptor",
        "reordered_descriptor",
        "count",
        "row",
        "row_order",
    ],
)
def test_sealed_fixture_refuses_incomplete_or_changed_artifacts(damage: str):
    fixture = _fixture()
    if damage == "missing":
        fixture["sealed_pages"].pop()
    elif damage == "reordered":
        fixture["sealed_pages"][1], fixture["sealed_pages"][2] = (
            fixture["sealed_pages"][2],
            fixture["sealed_pages"][1],
        )
    elif damage == "descriptor":
        fixture["sealed_pages"][0]["descriptors"][0]["body_bytes"] += 1
    elif damage == "missing_descriptor":
        fixture["sealed_pages"][0]["descriptors"].pop()
    elif damage == "duplicate_descriptor":
        fixture["sealed_pages"][0]["descriptors"][1] = deepcopy(
            fixture["sealed_pages"][0]["descriptors"][0]
        )
    elif damage == "reordered_descriptor":
        (
            fixture["sealed_pages"][0]["descriptors"][0],
            fixture["sealed_pages"][0]["descriptors"][1],
        ) = (
            fixture["sealed_pages"][0]["descriptors"][1],
            fixture["sealed_pages"][0]["descriptors"][0],
        )
    elif damage == "count":
        fixture["sealed_pages"][0]["header"]["transcript_row_count"] += 1
    elif damage == "row_order":
        fixture["sealed_pages"][2]["body"]["rows"].reverse()
    else:
        fixture["sealed_pages"][1]["body"]["rows"][0]["value"]["content"] += "!"
    with pytest.raises(ValueError):
        verify_sealed_pages(
            SealReceipt.model_validate(fixture["seal_receipt"]), _pages(fixture)
        )


def test_provider_binding_rejects_missing_nested_signed_status_schema():
    binding = deepcopy(_fixture()["seal_receipt"]["provider_binding"])
    del binding["signed_status"]["status"]["schema"]
    with pytest.raises(ValueError):
        ProviderBinding.model_validate(binding)


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":2}', b'{"n":NaN}', b'{"n":1e999}', b'"\xff"']
)
def test_strict_json_refuses_duplicate_nonfinite_and_invalid_utf8(raw: bytes):
    with pytest.raises(ValueError):
        strict_json_loads(raw)


def test_encoded_response_limit_counts_unicode_and_envelope():
    value = {"schema": "hermes.recovery-page/v1", "value": "\u00e9" * 65_000}
    assert len(bounded_response_bytes(value)) > 65_000
    assert len(bounded_response_bytes(value)) <= MAX_RESPONSE_BYTES
    with pytest.raises(ValueError):
        bounded_response_bytes({
            "schema": "hermes.recovery-page/v1",
            "value": "\u00e9" * 65_520,
        })


def test_sealed_result_refuses_receipt_that_exceeds_full_encoded_response():
    fixture = _fixture()["seal_result"]
    fixture["receipt"]["acknowledged_usage"]["cost_source"] = "x" * MAX_RESPONSE_BYTES
    with pytest.raises(ValueError):
        SealResult.model_validate(fixture)


def test_whole_row_exceeding_response_limit_is_refused():
    fixture = _fixture()
    page = deepcopy(fixture["sealed_pages"][1])
    page["body"]["rows"][0]["value"]["content"] = "x" * MAX_RESPONSE_BYTES
    row = page["body"]["rows"][0]
    row["row_sha256"] = document_sha256(
        "hermes.recovery.row/transcript/v1",
        {key: value for key, value in row.items() if key != "row_sha256"},
    )
    with pytest.raises(ValueError):
        DataArtifactPage.model_validate(page)


def test_fixed_message_and_snapshot_caps_refuse_overflow():
    fixture = _fixture()
    original = fixture["sealed_pages"][1]["body"]["rows"][0]
    rows = []
    for index in range(65):
        row = {**original, "row_index": index}
        row["row_sha256"] = document_sha256(
            "hermes.recovery.row/transcript/v1",
            {key: value for key, value in row.items() if key != "row_sha256"},
        )
        rows.append(row)
    assert (
        len(
            DataBody(
                data_index=0, kind="transcript", first_row_index=0, rows=rows[:64]
            ).rows
        )
        == 64
    )
    with pytest.raises(ValueError):
        DataBody(data_index=0, kind="transcript", first_row_index=0, rows=rows)
    receipt = fixture["seal_receipt"]
    receipt["snapshot_bytes"] = 16 * 1024 * 1024 + 1
    with pytest.raises(ValueError):
        SealReceipt.model_validate(receipt)
    with pytest.raises(ValueError):
        hash_rows("transcript", ({"x": 1} for _ in range(100_001)), max_rows=100_000)


def test_encoded_page_aggregate_guard_is_independent_of_snapshot_bytes(monkeypatch):
    fixture = _fixture()
    receipt = SealReceipt.model_validate(fixture["seal_receipt"])
    assert receipt.snapshot_bytes < 3_500
    monkeypatch.setattr(recovery_wire, "MAX_SNAPSHOT_BYTES", 3_500)
    with pytest.raises(ValueError, match="encoded sealed pages"):
        verify_sealed_pages(receipt, _pages(fixture))


def test_total_page_guard_refuses_4097_route_pages():
    receipt = _fixture()["seal_receipt"]
    receipt["manifest_page_count"] = 4_096
    receipt["data_page_count"] = 1
    with pytest.raises(ValueError):
        SealReceipt.model_validate(receipt)
