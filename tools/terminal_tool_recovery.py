"""Exact selected-workspace interception for an admitted protected tool call."""

from __future__ import annotations

import re
import json
from typing import Any

from agent.recovery_producers import current_lease, current_registry
from hermes_state_recovery import RecoveryRefused
from hermes_state_recovery_provider import (
    ProviderAdmissionValue, ProviderInvocationOutcome, ProviderInvocationRow, ProviderLedger,
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _current(provider: object, task_id: str, *, tool: bool):
    registry, lease = current_registry(), current_lease()
    if registry is None or lease is None or lease.registry is not registry:
        raise RecoveryRefused("invalid_provider_lease")
    if (lease._state != "running" or task_id != registry.scope.session_id
            or tool and lease.kind != "tool"):
        raise RecoveryRefused("invalid_provider_lease")
    capture = getattr(registry, "provider_capture", None)
    if capture is None or capture.require_selected() is not provider:
        raise RecoveryRefused("provider_selection_changed")
    ledger = ProviderLedger(registry.store)
    if ledger.admission(registry.scope) != capture.admission:
        raise RecoveryRefused("provider_admission_mismatch")
    phase = registry.store.db._read_one(
        "SELECT phase,reason_codes_json FROM recovery_sessions WHERE session_id=?",
        (registry.scope.session_id,))
    if phase is None or phase[0] != "open":
        raise RecoveryRefused("session_closing")
    try:
        reasons = json.loads(phase[1])
    except (TypeError, ValueError) as exc:
        raise RecoveryRefused("provider_inventory_invalid") from exc
    if (not isinstance(reasons, list) or len(reasons) > 32
            or any(type(reason) is not str for reason in reasons)):
        raise RecoveryRefused("provider_inventory_invalid")
    if "untracked_producer" in reasons or "unsupported_configuration" in reasons:
        raise RecoveryRefused("unsupported_configuration")
    return registry, lease, ledger, capture


def _create_row(registry) -> ProviderInvocationRow | None:
    db = registry.store.db
    row = db._read_one(
        "SELECT invocation_id,session_id,run_id,generation,producer_id,sequence,kind,state,"
        "create_invocation_id,container_id,container_attestation_sha256,exit_code,"
        "outcome_reason FROM recovery_provider_invocations WHERE session_id=? AND sequence=0",
        (registry.scope.session_id,))
    if row is None:
        return None
    try:
        value = ProviderInvocationRow.model_validate(dict(zip(ProviderInvocationRow.model_fields, row)))
    except (TypeError, ValueError) as exc:
        raise RecoveryRefused("provider_inventory_invalid") from exc
    if value.kind != "create_environment" or value.state != "returned":
        raise RecoveryRefused("provider_create_missing")
    count = db._read_one(
        "SELECT COUNT(*) FROM recovery_provider_invocations "
        "WHERE session_id=? AND kind='create_environment'", (registry.scope.session_id,))[0]
    if count != 1:
        raise RecoveryRefused("provider_inventory_invalid")
    return value


def _verified_readback(capture, readback: object, create: ProviderInvocationRow | None) -> None:
    try:
        admission = ProviderAdmissionValue.model_validate(
            readback.admission.model_dump(mode="json"))
        container_id = readback.container_id
        attestation = readback.container_attestation_sha256
        if (admission != capture.admission or readback.state != "bound"
                or readback.status_state != "active"
                or type(container_id) is not str or not container_id or len(container_id) > 255
                or type(attestation) is not str or _SHA256.fullmatch(attestation) is None
                or create is not None and (
                    create.container_id != container_id
                    or create.container_attestation_sha256 != attestation)):
            raise RecoveryRefused("provider_binding_mismatch")
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, RecoveryRefused):
            raise
        raise RecoveryRefused("provider_binding_mismatch") from exc


def _verified_environment(provider: object, environment: object, capture) -> None:
    try:
        if (type(environment).__name__ != "WorkspaceEnvironment"
                or type(environment).__module__.split(".")[-1] != "workspace_provider"
                or environment._provider is not provider._core
                or environment._reference.model_dump(mode="json")
                != capture.admission.reference.model_dump(mode="json")):
            raise RecoveryRefused("provider_environment_mismatch")
    except AttributeError as exc:
        raise RecoveryRefused("provider_environment_mismatch") from exc


class ProtectedWorkspaceEnvironment:
    """One local wrapper; each physical execute uses the current member's tool lease."""

    def __init__(self, environment: object, provider: object, scope, create_id: str):
        self._environment = environment
        self._provider = provider
        self._scope = scope
        self._create_id = create_id
        self._detached = False
        self.cwd = environment.cwd
        self.timeout = environment.timeout
        self._hermes_backend_name = "byf_workspace"

    def validate_current(self, task_id: str) -> None:
        if self._detached or task_id != self._scope.session_id:
            raise RecoveryRefused("provider_environment_mismatch")
        registry, _lease, _ledger, capture = _current(
            self._provider, task_id, tool=False)
        if registry.scope != self._scope:
            raise RecoveryRefused("provider_environment_mismatch")
        create = _create_row(registry)
        if create is None or create.invocation_id != self._create_id:
            raise RecoveryRefused("provider_create_missing")
        _verified_environment(self._provider, self._environment, capture)

    def execute(self, command: str, *args: Any, **kwargs: Any) -> dict:
        self.validate_current(self._scope.session_id)
        registry, lease, ledger, _capture = _current(
            self._provider, self._scope.session_id, tool=True)
        strict_execute = getattr(self._environment, "execute_recovery", None)
        if not callable(strict_execute):
            raise RecoveryRefused("unsupported_provider")
        cap = ledger.begin(registry.scope, registry.run_id, registry.generation,
                           lease.producer_id, "execute", self._create_id)
        try:
            result = strict_execute(command, *args, **kwargs)
        except BaseException:
            try:
                ledger.finish(cap, ProviderInvocationOutcome(
                    "unknown", reason="provider_exception"))
            finally:
                raise
        if (type(result) is not dict or type(result.get("returncode")) is not int
                or type(result.get("exit_code")) is not int
                or result["returncode"] != result["exit_code"]
                or not -(2**31) <= result["returncode"] < 2**31):
            ledger.finish(cap, ProviderInvocationOutcome("unknown", reason="lost_result"))
            raise RecoveryRefused("provider_result_unknown")
        ledger.finish(cap, ProviderInvocationOutcome("returned", exit_code=result["returncode"]))
        return dict(result)

    def cleanup(self, *, force_remove: bool = False) -> None:
        self._detached = True
        self._environment.cleanup(force_remove=force_remove)

    def get_temp_dir(self) -> str:
        return self._environment.get_temp_dir()


def build_protected_plugin_env(
    provider: object, *, task_id: str, cwd: str, timeout: int,
    image: str | None, container_config: dict,
) -> ProtectedWorkspaceEnvironment:
    registry, lease, ledger, capture = _current(provider, task_id, tool=True)
    create = _create_row(registry)
    if create is None:
        cap = ledger.begin(registry.scope, registry.run_id, registry.generation,
                           lease.producer_id, "create_environment")
        try:
            environment = provider.create_environment(
                cwd=cwd, timeout=timeout, task_id=task_id, image=image,
                container_config=container_config)
            _verified_environment(provider, environment, capture)
            readback = provider.read_recovery_binding_wire(capture.admission.canonical_bytes())
            _verified_readback(capture, readback, None)
        except BaseException:
            try:
                ledger.finish(cap, ProviderInvocationOutcome(
                    "unknown", reason="provider_exception"))
            finally:
                raise
        ledger.finish(cap, ProviderInvocationOutcome(
            "returned", container_id=readback.container_id,
            container_attestation_sha256=readback.container_attestation_sha256))
        create_id = cap.invocation_id
    else:
        attach = getattr(provider, "attach_recovery_environment", None)
        if not callable(attach):
            raise RecoveryRefused("unsupported_provider")
        environment, readback = attach(capture.admission.canonical_bytes(), timeout=timeout)
        _verified_readback(capture, readback, create)
        _verified_environment(provider, environment, capture)
        create_id = create.invocation_id
    return ProtectedWorkspaceEnvironment(environment, provider, registry.scope, create_id)
