"""Strict wire contract for the first supported recovery protocol."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


class _Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RecoveryAdmission(_Wire):
    schema_: Literal["hermes.recovery/v1"] = Field(alias="schema")
    generation: Literal[0, 1]
    parent_run_id: str | None

    @field_validator("parent_run_id")
    @classmethod
    def _nonempty_parent(cls, value: str | None) -> str | None:
        if value == "":
            raise ValueError("parent_run_id cannot be empty")
        return value


class RecoveryMember(_Wire):
    run_id: str = Field(min_length=1)
    generation: Literal[0, 1]
    parent_run_id: str | None
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    producer_state: Literal["open", "closed", "incomplete"]

    @model_validator(mode="after")
    def _lineage(self):
        if (self.generation == 0) != (self.parent_run_id is None):
            raise ValueError("member lineage does not match generation")
        return self


class SealRequest(_Wire):
    request_id: str
    session_id: str
    run_ids: list[str] = Field(min_length=1, max_length=2)
    expected_membership_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("request_id")
    @classmethod
    def _uuid_request(cls, value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("request_id must be a canonical UUID")
        return value

    @model_validator(mode="after")
    def _unique_members(self):
        if len(set(self.run_ids)) != len(self.run_ids) or any(not run_id for run_id in self.run_ids):
            raise ValueError("run IDs must be distinct and nonempty")
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
    billing_provider: str
    billing_mode: str


class ProviderBinding(_Wire):
    provider: Literal["byf_workspace"]
    state: Literal["unused", "bound"]
    binding_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    workspace_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    attestation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    container_id: str | None = None

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
    gateway_incarnation: str
    profile: str
    scope_digest: str
    session_id: str
    members: list[RecoveryMember]
    sealed_at: float
    revision: int
    membership_sha256: str
    transcript_sha256: str
    snapshot_manifest_sha256: str
    accounting_sha256: str
    send_ledger_sha256: str
    acknowledged_usage: AcknowledgedUsage
    provider_binding: ProviderBinding
    no_calls: bool

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
    reasons: list[str] = Field(max_length=16)
    receipt: SealReceipt | None = None

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


class SnapshotPage(_Wire):
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    page_index: int = Field(ge=0)
    rows: list[SnapshotRow] = Field(max_length=64)
    next_page: int | None = Field(default=None, ge=0)
