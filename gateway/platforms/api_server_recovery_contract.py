"""Strict wire contract for the first supported recovery protocol."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from types import MappingProxyType
from typing import Annotated, Literal, Union, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_serializer, field_validator, model_validator

from gateway.platforms.api_server_recovery_artifacts import (
    MAX_ACCOUNTING_BYTES,
    MAX_DOCUMENT_BYTES,
    MAX_OTHER_PAGE_ROWS,
    MAX_RESPONSE_BYTES,
    MAX_ROUTE_PAGES,
    MAX_SNAPSHOT_BYTES,
    MAX_TRANSCRIPT_PAGE_ROWS,
    MAX_TRANSCRIPT_ROWS,
    SECTION_TAGS,
    bounded_response_bytes,
    canonical_json_bytes,
    document_sha256,
    hash_rows,
    manifest_sha256,
)


class _Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _immutable_array(value: object) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("expected an array")
    return tuple(cast(list[object] | tuple[object, ...], value))


def _freeze_json(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item)
                                 for key, item in cast(dict[str, object], value).items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in cast(list[object], value))
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, MappingProxyType):
        return {key: _thaw_json(item)
                for key, item in cast(MappingProxyType[str, object], value).items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in cast(tuple[object, ...], value)]
    return value


RecoveryReason = Literal[
    "lost_producer_owner", "missing_membership", "unknown_send_outcome",
    "failed_usage_acknowledgement", "untracked_producer", "unsupported_configuration",
    "unclosed_producer", "untracked_write", "producer_open", "usage_pending", "snapshot_pending",
]


class RecoveryAdmission(_Wire):
    schema_: Literal["hermes.recovery/v1"] = Field(alias="schema")
    generation: Literal[0, 1]
    parent_run_id: str | None = Field(max_length=255)

    @field_validator("parent_run_id")
    @classmethod
    def _nonempty_parent(cls, value: str | None) -> str | None:
        if value == "":
            raise ValueError("parent_run_id cannot be empty")
        return value


class RecoveryMember(_Wire):
    run_id: str = Field(min_length=1, max_length=255)
    generation: Literal[0, 1]
    parent_run_id: str | None = Field(max_length=255)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    producer_state: Literal["open", "closed", "incomplete"]

    @model_validator(mode="after")
    def _lineage(self):
        if (self.generation == 0) != (self.parent_run_id is None):
            raise ValueError("member lineage does not match generation")
        if self.parent_run_id == "":
            raise ValueError("member parent cannot be empty")
        return self


class SealRequest(_Wire):
    request_id: str
    session_id: str = Field(min_length=1, max_length=255)
    run_ids: tuple[str, ...] = Field(min_length=1, max_length=2)
    expected_membership_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    _freeze_runs = field_validator("run_ids", mode="before")(_immutable_array)

    @field_validator("request_id")
    @classmethod
    def _uuid_request(cls, value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("request_id must be a canonical UUID")
        return value

    @model_validator(mode="after")
    def _unique_members(self):
        if (len(set(self.run_ids)) != len(self.run_ids)
                or any(not run_id or len(run_id) > 255 for run_id in self.run_ids)):
            raise ValueError("run IDs must be distinct and bounded")
        return self


class AcknowledgedUsage(_Wire):
    api_call_count: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cache_read_tokens: int = Field(ge=0)
    cache_write_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0, allow_inf_nan=False)
    actual_cost_usd: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    cost_status: str | None = None
    cost_source: str | None = None
    billing_provider: str = Field(min_length=1, max_length=128)
    billing_mode: str = Field(min_length=1, max_length=128)


class WorkspaceRefWire(_Wire):
    lease_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    grant_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SignedStatusValue(_Wire):
    schema_: Literal["byf.workspace-status/v1"] = Field(alias="schema")
    reference: WorkspaceRefWire
    session_id: str = Field(min_length=1, max_length=255)
    epoch_id: str = Field(min_length=1, max_length=255)
    revision: int = Field(gt=0)
    previous_state: Literal["active", "suspended", "sealed", "reaped"] | None
    state: Literal["active", "suspended", "sealed", "reaped"]
    valid_until: str = Field(min_length=1, max_length=64)
    maximum_expires_at: str = Field(min_length=1, max_length=64)


class SignedStatusWire(_Wire):
    schema_: Literal["byf.signed-workspace-status/v1"] = Field(alias="schema")
    status: SignedStatusValue
    key_id: str = Field(min_length=1, max_length=128)
    hmac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProviderBinding(_Wire):
    provider: Literal["byf_workspace"]
    state: Literal["unused", "bound"]
    session_id: str = Field(min_length=1, max_length=255)
    hermes_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: WorkspaceRefWire
    status_state: Literal["active", "suspended", "sealed", "reaped"]
    status_revision: int = Field(gt=0)
    signed_status: SignedStatusWire
    signed_status_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    container_id: str | None = Field(default=None, max_length=255)
    container_attestation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    invocation_count: int = Field(ge=0)
    invocations_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _binding_consistency(self):
        status = self.signed_status.status
        if (self.reference.provider_sha256 != self.provider_sha256
                or status.reference != self.reference
                or status.session_id != self.session_id
                or status.state != self.status_state
                or status.revision != self.status_revision
                or hashlib.sha256(canonical_json_bytes(self.signed_status)).hexdigest()
                != self.signed_status_sha256):
            raise ValueError("provider signed status conflicts with exact association")
        if self.state == "unused":
            if (self.container_id is not None or self.container_attestation_sha256 is not None
                    or self.invocation_count != 0
                    or self.invocations_sha256 != hash_rows("provider_invocations", ()).sha256):
                raise ValueError("unused provider requires proved empty creation inventory")
        elif (not self.container_id or self.container_attestation_sha256 is None
                or self.invocation_count == 0):
            raise ValueError("bound provider requires container and inventoried creation")
        if document_sha256("hermes.recovery.provider-binding/v1",
                           self.model_dump(mode="json", by_alias=True,
                                           exclude={"binding_sha256"})) != self.binding_sha256:
            raise ValueError("provider binding digest does not match typed fields")
        return self


class SealReceipt(_Wire):
    schema_: Literal["hermes.recovery-receipt/v1"] = Field(alias="schema")
    store_id: str
    gateway_incarnation: str = Field(min_length=1, max_length=128)
    profile: str = Field(min_length=1, max_length=128)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_id: str = Field(min_length=1, max_length=255)
    members: tuple[RecoveryMember, ...] = Field(min_length=1, max_length=2)
    sealed_at: float = Field(gt=0, allow_inf_nan=False)
    revision: int = Field(ge=1, le=2**63 - 1)
    membership_sha256: str
    transcript_sha256: str
    snapshot_manifest_sha256: str
    accounting_sha256: str
    send_ledger_sha256: str
    manifest_page_count: int = Field(ge=1, le=MAX_ROUTE_PAGES)
    data_page_count: int = Field(ge=0, le=MAX_ROUTE_PAGES)
    transcript_row_count: int = Field(ge=0, le=MAX_TRANSCRIPT_ROWS)
    accounting_row_count: int = Field(ge=1)
    send_row_count: int = Field(ge=0)
    provider_invocation_row_count: int = Field(ge=0)
    snapshot_bytes: int = Field(ge=1, le=MAX_SNAPSHOT_BYTES)
    acknowledged_usage: AcknowledgedUsage
    provider_binding: ProviderBinding
    no_calls: bool

    _freeze_members = field_validator("members", mode="before")(_immutable_array)

    @field_validator("store_id")
    @classmethod
    def _uuid_store(cls, value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("store_id must be a canonical UUID")
        return value

    @field_validator("membership_sha256", "transcript_sha256", "snapshot_manifest_sha256",
                     "accounting_sha256", "send_ledger_sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError("digest must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def _member_order(self):
        from hermes_state_recovery import membership_sha256

        if ([member.generation for member in self.members] != list(range(len(self.members)))
                or membership_sha256([member.run_id for member in self.members]) != self.membership_sha256):
            raise ValueError("receipt membership is inconsistent")
        if (self.manifest_page_count + self.data_page_count > MAX_ROUTE_PAGES
                or self.provider_invocation_row_count != self.provider_binding.invocation_count
                or self.provider_binding.session_id != self.session_id
                or self.no_calls != (self.send_row_count == 0)):
            raise ValueError("receipt artifact inventory is inconsistent")
        if len(canonical_json_bytes(self)) > MAX_DOCUMENT_BYTES:
            raise ValueError("receipt document exceeds 1 MiB")
        return self


class SealResult(_Wire):
    schema_: Literal["hermes.recovery/v1"] = Field(alias="schema")
    state: Literal["pending", "unsupported", "sealed"]
    request_id: str
    reasons: tuple[RecoveryReason, ...] = Field(max_length=16)
    receipt: SealReceipt | None = None

    _freeze_reasons = field_validator("reasons", mode="before")(_immutable_array)

    @field_validator("request_id")
    @classmethod
    def _uuid_request(cls, value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("request_id must be a canonical UUID")
        return value

    @model_validator(mode="after")
    def _receipt_consistency(self):
        if (self.state == "sealed") != (self.receipt is not None):
            raise ValueError("receipt is required exactly when sealed")
        if self.state == "sealed" and self.reasons:
            raise ValueError("sealed result cannot have pending reasons")
        bounded_response_bytes(self)
        return self


# Task 1's message-only SnapshotPage was provisional and never served. Task 4
# replaces it with a typed, retrievable sealed-artifact stream on the same route.
ArtifactKind = Literal["transcript", "accounting", "send_ledger", "provider_invocations"]


class ArtifactRow(_Wire):
    row_index: int = Field(ge=0)
    kind: ArtifactKind
    value: dict[str, JsonValue]
    row_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _valid_digest_and_immutable_value(self):
        expected = document_sha256(
            f"hermes.recovery.row/{self.kind}/v1",
            {"row_index": self.row_index, "kind": self.kind, "value": _thaw_json(self.value)},
        )
        if self.row_sha256 != expected:
            raise ValueError("artifact row digest does not match full value")
        object.__setattr__(self, "value", _freeze_json(self.value))
        bounded_response_bytes(self)
        return self

    @field_serializer("value")
    def _serialize_value(self, value: object) -> object:
        return _thaw_json(value)


class DataBody(_Wire):
    data_index: int = Field(ge=0, le=MAX_ROUTE_PAGES)
    kind: ArtifactKind
    first_row_index: int = Field(ge=0)
    rows: tuple[ArtifactRow, ...] = Field(min_length=1, max_length=MAX_OTHER_PAGE_ROWS)

    _freeze_rows = field_validator("rows", mode="before")(_immutable_array)

    @model_validator(mode="after")
    def _whole_ordered_rows(self):
        if self.kind == "transcript" and len(self.rows) > MAX_TRANSCRIPT_PAGE_ROWS:
            raise ValueError("transcript page exceeds 64 whole messages")
        if any(row.kind != self.kind or row.row_index != self.first_row_index + offset
               for offset, row in enumerate(self.rows)):
            raise ValueError("data body row kind or index is inconsistent")
        return self


class PageDescriptor(_Wire):
    data_index: int = Field(ge=0, le=MAX_ROUTE_PAGES)
    kind: ArtifactKind
    first_row_index: int = Field(ge=0)
    row_count: int = Field(ge=1, le=MAX_OTHER_PAGE_ROWS)
    body_bytes: int = Field(ge=1, le=MAX_RESPONSE_BYTES)
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ManifestHeader(_Wire):
    data_page_count: int = Field(ge=0, le=MAX_ROUTE_PAGES)
    transcript_row_count: int = Field(ge=0, le=MAX_TRANSCRIPT_ROWS)
    accounting_row_count: int = Field(ge=1)
    send_row_count: int = Field(ge=0)
    provider_invocation_row_count: int = Field(ge=0)


class ManifestArtifactPage(_Wire):
    schema_: Literal["hermes.recovery-page/v1"] = Field(alias="schema")
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    route_page: int = Field(ge=0, lt=MAX_ROUTE_PAGES)
    kind: Literal["manifest"] = "manifest"
    manifest_index: int = Field(ge=0, lt=MAX_ROUTE_PAGES)
    header: ManifestHeader | None = None
    descriptors: tuple[PageDescriptor, ...] = Field(max_length=MAX_OTHER_PAGE_ROWS)
    next_page: int | None = Field(default=None, ge=0, lt=MAX_ROUTE_PAGES)

    _freeze_descriptors = field_validator("descriptors", mode="before")(_immutable_array)

    @model_validator(mode="after")
    def _header_only_on_first_page(self):
        if self.route_page != self.manifest_index or (self.header is None) != (self.manifest_index != 0):
            raise ValueError("manifest header or route index is inconsistent")
        bounded_response_bytes(self)
        return self


class DataArtifactPage(_Wire):
    schema_: Literal["hermes.recovery-page/v1"] = Field(alias="schema")
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    route_page: int = Field(ge=0, lt=MAX_ROUTE_PAGES)
    kind: Literal["data"] = "data"
    body: DataBody
    next_page: int | None = Field(default=None, ge=0, lt=MAX_ROUTE_PAGES)

    @model_validator(mode="after")
    def _bounded_response(self):
        bounded_response_bytes(self)
        return self


SealedArtifactPage = Annotated[Union[ManifestArtifactPage, DataArtifactPage], Field(discriminator="kind")]


def descriptor_for_body(body: DataBody) -> PageDescriptor:
    encoded = canonical_json_bytes(body)
    return PageDescriptor(
        data_index=body.data_index, kind=body.kind,
        first_row_index=body.first_row_index, row_count=len(body.rows),
        body_bytes=len(encoded),
        body_sha256=document_sha256("hermes.recovery.data-page/v1", body),
    )


def receipt_sha256(receipt: SealReceipt) -> str:
    return document_sha256("hermes.recovery.receipt/v1", receipt)


def verify_sealed_pages(receipt: SealReceipt, pages: Iterable[SealedArtifactPage]) -> None:
    """Validate complete immutable pages with bounded descriptors and streamed row hashes."""
    expected_hash = receipt_sha256(receipt)
    iterator = iter(pages)
    encoded_total = 0
    descriptors: list[PageDescriptor] = []
    header: ManifestHeader | None = None
    total_pages = receipt.manifest_page_count + receipt.data_page_count
    for route_page in range(receipt.manifest_page_count):
        page = next(iterator, None)
        if not isinstance(page, ManifestArtifactPage):
            raise ValueError("missing or incorrectly typed manifest page")
        encoded_total += len(bounded_response_bytes(page))
        if encoded_total > MAX_SNAPSHOT_BYTES:
            raise ValueError("encoded sealed pages exceed 16 MiB")
        if (page.receipt_sha256 != expected_hash or page.route_page != route_page
                or page.manifest_index != route_page
                or page.next_page != (route_page + 1 if route_page + 1 < total_pages else None)):
            raise ValueError("manifest page receipt or route sequence changed")
        if route_page == 0:
            header = page.header
        descriptors.extend(page.descriptors)
        if len(descriptors) > MAX_ROUTE_PAGES:
            raise ValueError("manifest descriptor count exceeds fixed bound")
    if header is None or header.data_page_count != receipt.data_page_count:
        raise ValueError("manifest header is missing or inconsistent")
    expected_counts = (
        receipt.transcript_row_count, receipt.accounting_row_count,
        receipt.send_row_count, receipt.provider_invocation_row_count,
    )
    actual_counts = (
        header.transcript_row_count, header.accounting_row_count,
        header.send_row_count, header.provider_invocation_row_count,
    )
    if actual_counts != expected_counts or len(descriptors) != receipt.data_page_count:
        raise ValueError("manifest section counts or data pages are incomplete")
    manifest = manifest_sha256(header, descriptors)
    if manifest.sha256 != receipt.snapshot_manifest_sha256:
        raise ValueError("manifest root changed")
    section_order = tuple(SECTION_TAGS)
    section_digests = {
        kind: hashlib.sha256(SECTION_TAGS[kind].encode("ascii") + b"\n")
        for kind in section_order
    }
    section_counts = dict.fromkeys(section_order, 0)
    section_bytes = dict.fromkeys(section_order, 0)
    last_section = 0
    for data_index, descriptor in enumerate(descriptors):
        page = next(iterator, None)
        if not isinstance(page, DataArtifactPage):
            raise ValueError("missing or incorrectly typed data page")
        encoded_total += len(bounded_response_bytes(page))
        if encoded_total > MAX_SNAPSHOT_BYTES:
            raise ValueError("encoded sealed pages exceed 16 MiB")
        route_page = receipt.manifest_page_count + data_index
        if (page.receipt_sha256 != expected_hash or page.route_page != route_page
                or page.next_page != (route_page + 1 if route_page + 1 < total_pages else None)
                or page.body.data_index != data_index
                or descriptor != descriptor_for_body(page.body)):
            raise ValueError("data page descriptor or route sequence changed")
        kind = page.body.kind
        order = section_order.index(kind)
        if order < last_section or page.body.first_row_index != section_counts[kind]:
            raise ValueError("data section or row order changed")
        last_section = order
        for row in page.body.rows:
            line = canonical_json_bytes(row) + b"\n"
            section_digests[kind].update(line)
            section_counts[kind] += 1
            section_bytes[kind] += len(line)
            if (kind == "transcript" and section_counts[kind] > MAX_TRANSCRIPT_ROWS
                    or kind == "accounting" and section_bytes[kind] > MAX_ACCOUNTING_BYTES):
                raise ValueError("sealed section exceeds its fixed bound")
    if next(iterator, None) is not None:
        raise ValueError("sealed page stream contains unexpected extra page")
    if tuple(section_counts[kind] for kind in section_order) != expected_counts:
        raise ValueError("sealed row inventory is incomplete")
    if manifest.byte_count + sum(section_bytes.values()) != receipt.snapshot_bytes:
        raise ValueError("canonical snapshot byte count changed")
    expected_roots = (
        receipt.transcript_sha256, receipt.accounting_sha256,
        receipt.send_ledger_sha256, receipt.provider_binding.invocations_sha256,
    )
    if tuple(section_digests[kind].hexdigest() for kind in section_order) != expected_roots:
        raise ValueError("independent sealed section root changed")
