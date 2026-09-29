"""Strict ordinary-session identity resolution followed by one durable claim.

Callers must dispatch the returned tip, without independently re-resolving it
between this claim and their first effect. A later changed target needs a new
claim before use.
"""

from __future__ import annotations

import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from hermes_state_recovery import RecoveryRefused
from hermes_state_recovery_exclusions import (
    EXCLUSION_NAMES,
    OrdinaryClaimReceipt,
    _canonical_exclusion_shape,
    claim_ordinary_sessions,
)


@dataclass(frozen=True, slots=True)
class ClaimedOrdinarySessions:
    original_ids: tuple[str, ...]
    resolved_ids: tuple[str, ...]
    receipt: OrdinaryClaimReceipt


def selected_state_db_path(session_db: object | None) -> Path:
    """Use the selected DB when present; an invalid selected object cannot redirect a claim."""
    if session_db is None:
        from hermes_constants import get_hermes_home

        return get_hermes_home() / "state.db"
    raw = getattr(session_db, "db_path", None)
    if isinstance(raw, Path):
        return raw
    if type(raw) is str and raw:
        return Path(raw)
    raise RecoveryRefused("protected_session_authority_unavailable")


def _has_no_session_catalog(path: Path) -> bool:
    """Only an absent or exact empty/bootstrap catalog has no alias to follow."""
    try:
        identity = path.lstat()
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc
    if not stat.S_ISREG(identity.st_mode) or identity.st_size == 0:
        raise RecoveryRefused("protected_session_authority_unavailable")
    from hermes_state import has_invalid_sqlite_header_preopen

    if has_invalid_sqlite_header_preopen(path):
        raise RecoveryRefused("protected_session_authority_unavailable")
    try:
        with closing(
            sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)
        ) as conn:
            conn.execute("PRAGMA query_only=ON")
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
            ).fetchall()
            names = {row[0] for row in rows}
            if not names:
                return True
            if names == EXCLUSION_NAMES:
                if not _canonical_exclusion_shape(conn):
                    raise RecoveryRefused("protected_session_authority_unavailable")
                return True
            return False
    except sqlite3.DatabaseError as exc:
        raise RecoveryRefused("protected_session_authority_unavailable") from exc


def claim_exact_ordinary(
    db_path: Path, session_ids: tuple[str, ...]
) -> ClaimedOrdinarySessions:
    """Resolve all actual IDs strictly, then claim originals and tips together."""
    if (
        not isinstance(db_path, Path)
        or type(session_ids) is not tuple
        or not session_ids
        or any(type(sid) is not str or not 1 <= len(sid) <= 255 for sid in session_ids)
    ):
        raise RecoveryRefused("invalid_ordinary_identity")
    originals = tuple(dict.fromkeys(session_ids))
    if _has_no_session_catalog(db_path):
        resolved = originals
    else:
        from hermes_recovery_refusal import readonly_resume_session

        resolved = tuple(
            readonly_resume_session(sid, db_path=db_path) for sid in originals
        )
    receipt = claim_ordinary_sessions(
        db_path, tuple(dict.fromkeys((*originals, *resolved)))
    )
    return ClaimedOrdinarySessions(originals, resolved, receipt)


def resolve_declared_ordinary(db_path: Path, session_key: str) -> str | None:
    """Resolve an alias without treating a bootstrap-only catalog as corrupt sessions."""
    if not isinstance(db_path, Path) or type(session_key) is not str or not session_key:
        raise RecoveryRefused("invalid_ordinary_identity")
    if _has_no_session_catalog(db_path):
        return None
    from hermes_recovery_refusal import readonly_declared_session

    return readonly_declared_session(session_key, db_path=db_path)
