"""The Config B identity, and the authorization check every stage runs first (section 13).

    python -m aegis.config_b.identity   # show the identity and whether the signed addendum matches it

The identity covers:
- the Config A identity it inherits;
- the Config B source files;
- the Config A experiment code Config B reuses, which is outside Config A's frozen identity;
- the scenario bank manifest;
- the protocol constants.

The signed identity addendum in ``config_b.json`` must name it before any stage may run.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from aegis.config_b import protocol
from aegis.frozen import frozen_digest
from aegis.provenance import PACKAGE_DIR

CONFIG_B_FILES = tuple(sorted(f"config_b/{p.name}" for p in (PACKAGE_DIR / "config_b").glob("*.py")))
REUSED_FILES = ("experiments/artifacts.py", "experiments/baseline.py", "experiments/selection.py")


def _sha(name: str) -> str:
    return hashlib.sha256((PACKAGE_DIR / name).read_text(encoding="utf-8").replace("\r\n", "\n").encode()).hexdigest()


def current_identity() -> dict:
    constants = {
        name: getattr(protocol, name) for name in (
            "DATASET", "HELD_OUT_FAMILIES", "FOLD_SEEDS", "EPISODES_PER_FOLD_SEED", "BANK_MANIFEST_SHA256",
            "MAPPED_FAMILIES", "ARMS", "MAX_REPLAYS_PER_ROW", "RATIOS", "RULE_TREATMENTS", "OUTSIDE_RULE",
            "STAGES", "STAGE_CEILINGS", "APPROVED_PLANNING_BUDGET", "PLANNING_CEILING", "IN_STAGE_STOP", "HARD_STOP",
        )
    }
    constants["MAPPING"] = {f"{k[0]}/{k[1]}": v for k, v in protocol.MAPPING.items()}
    return json.loads(json.dumps({
        "config_a": frozen_digest(),
        "config_b_sha256": {name: _sha(name) for name in CONFIG_B_FILES},
        "reused_sha256": {name: _sha(name) for name in REUSED_FILES},
        "protocol": constants,
    }, default=list))


def digest() -> str:
    return hashlib.sha256(json.dumps(current_identity(), sort_keys=True).encode()).hexdigest()[:16]


def _utc(value: str, what: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise PermissionError(f"{what} is not a UTC timestamp: {value!r}") from None


def authorization(stage: str, path: Path = protocol.AMENDMENT) -> dict:
    """Default-deny. Every condition must hold, or ``PermissionError``.

    - The amendment is registered.
    - Every Config B amendment is signed by the owner.
    - The identity addendum is signed and names the current identity.
    - ``stage`` is authorized by the owner after the addendum was signed. The ``report`` step needs stage 5.

    It returns the compute approvals in force: the approved budget, and whether going past 153 CPU-h is
    authorized.
    """
    record = json.loads(path.read_text(encoding="utf-8"))
    owner = record.get("registered_by")
    if not owner or not record.get("registered_utc") or record.get("status") != "registered":
        raise PermissionError("the Config B amendment is not registered")
    registered = _utc(record["registered_utc"], "registered_utc")
    for amendment in record.get("amendments", []):
        if amendment.get("amended_by") != owner or not amendment.get("amended_utc"):
            raise PermissionError(f"Config B amendment {amendment.get('number')} is not signed by {owner}")
    addendum = record.get("identity_addendum") or {}
    if addendum.get("signed_by") != owner or not addendum.get("signed_utc"):
        raise PermissionError("no identity addendum signed by the owner; no stage may run")
    if addendum.get("config_b_identity") != digest():
        raise PermissionError(f"the Config B identity is {digest()}, not the signed {addendum.get('config_b_identity')}")
    signed = _utc(addendum["signed_utc"], "identity_addendum.signed_utc")
    if signed < registered:
        raise PermissionError("the identity addendum predates the registration")
    needed = "5" if stage == "report" else stage
    granted = [a for a in record.get("stage_authorizations", [])
               if needed in a.get("stages", []) and a.get("authorized_by") == owner and a.get("authorized_utc")
               and _utc(a["authorized_utc"], "authorized_utc") >= signed]
    if not granted:
        raise PermissionError(f"stage {needed} is not authorized by {owner} after the identity addendum")
    approvals = [a for a in record.get("compute_approvals", []) if a.get("approved_by") == owner and a.get("approved_utc")]
    latest = max(approvals, key=lambda a: _utc(a["approved_utc"], "approved_utc"), default={})
    return {"approved_budget": float(latest.get("approved_budget", protocol.APPROVED_PLANNING_BUDGET)),
            "past_planning_ceiling": bool(latest.get("past_planning_ceiling", False))}


def main() -> None:
    record = json.loads(protocol.AMENDMENT.read_text(encoding="utf-8"))
    addendum = record.get("identity_addendum") or {}
    recorded, signed = addendum.get("config_b_identity"), bool(addendum.get("signed_by") and addendum.get("signed_utc"))
    print(f"Config B identity: {digest()}")
    if recorded != digest():
        print(f"Does not match the identity addendum (recorded: {recorded})")
    else:
        print("Matches the identity addendum, " + ("signed" if signed else "which is NOT signed: no stage may run"))


if __name__ == "__main__":
    main()
