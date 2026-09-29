"""Strict wire contract for the first supported recovery protocol."""

from __future__ import annotations

from types import MappingProxyType
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_serializer, field_validator, model_validator


class _Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _immutable_array(value):
    if not isinstance(value, (list, tuple)):
        raise ValueError("expected an array")
    return tuple(value)


def _freeze_json(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value):
    if isinstance(value, MappingProxyType):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
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


class ProviderBinding(_Wire):
    provider: Literal["byf_workspace"]
    state: Literal["unused", "bound"]
    binding_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    workspace_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    attestation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    container_id: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def _binding_consistency(self):
        evidence = (self.binding_sha256, self.workspace_sha256, self.attestation_sha256)
        if self.state == "bound" and any(value is None for value in evidence):
            raise ValueError("bound provider requires attested evidence")
        if self.state == "unused" and (any(value is not None for value in evidence) or self.container_id):
            raise ValueError("unused provider cannot claim a binding")
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
        return self


class SnapshotRow(_Wire):
    row_index: int = Field(ge=0)
    row_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    message: dict[str, JsonValue]

    @model_validator(mode="after")
    def _freeze_message(self):
        object.__setattr__(self, "message", _freeze_json(self.message))
        return self

    @field_serializer("message")
    def _serialize_message(self, value):
        return _thaw_json(value)


class SnapshotPage(_Wire):
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    page_index: int = Field(ge=0)
    rows: tuple[SnapshotRow, ...] = Field(max_length=64)
    next_page: int | None = Field(default=None, ge=0)

    _freeze_rows = field_validator("rows", mode="before")(_immutable_array)
