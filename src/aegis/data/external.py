"""The only way to load an external test set, so it is touched once and on the record.

An external dataset is loaded through ``guarded_load``, which denies access by default. It loads only when
both of these hold:

1. **The pre-registration** exists, names this dataset, has every required field and only signed amendments,
   and records (directly or through its latest amendment) the frozen Config A identity that the current
   configuration and code still match.
2. **A Phase 5 opening authorization**, a separate file beside the pre-registration
   (``<name>.opening.json``), is attested by the registered owner. Signing amendments never authorizes opening.
   The authorization is bound to the exact pre-registration file, confirms every opening condition of plan
   section 9.2, and lists the exact frozen identity of every configuration authorized for external evaluation,
   each matching the identity recorded by signed amendment.

Every attempt, refused or not, is appended to an access log beside the pre-registration file.

**Limitation: attestations, not cryptographic signatures.** A "signature" here, on an amendment
(``amended_by``, ``amended_utc``) or on the opening authorization (``authorized_by``, ``authorized_utc``),
is a name and a UTC timestamp written in a JSON file. The guard checks that they are present, well formed,
name the registered owner and are consistent in time, and the authorization is bound to the exact
pre-registration by its hash. **It does not authenticate anyone.** It verifies no cryptographic signature and no
signed commit, and anyone who can write these files can write these fields. Their integrity rests on the
reviewed git history, in which the project owner commits them. The guard prevents accidental or premature
opening, not deliberate circumvention.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from aegis.config import BaselineConfig
from aegis.frozen import frozen_digest, verify_config_a

EXTERNAL_DATASETS = ("cse_cic_ids2018",)
REQUIRED_FIELDS = (
    "dataset", "release", "frozen_config_a", "registered_utc", "registered_by", "attempted_handling",
    "inspection_allowed", "primary_metric", "evaluation_views", "comparisons", "shortcut_rule",
)
# Plan section 9.2: each condition must be confirmed, by name, in the opening authorization.
OPENING_CONDITIONS = (
    "9.2.1_every_compared_configuration_frozen",
    "9.2.2_2018_loader_exists_and_frozen",
    "9.2.3_evaluation_code_exists_and_frozen",
    "9.2.4_development_run_of_no_extractor_features_reported",
)
_IDENTITY = re.compile(r"[0-9a-f]{16}")
_UTC = "%Y-%m-%dT%H:%M:%SZ"
T = TypeVar("T")


def access_log_path(preregistration: Path) -> Path:
    return preregistration.with_name(preregistration.stem + ".access.jsonl")


def _log(preregistration: Path, entry: dict) -> None:
    with access_log_path(preregistration).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def check_preregistration(path: Path, dataset: str, config: BaselineConfig) -> dict:
    """Return the pre-registration if it allows loading this dataset now; raise otherwise."""
    if dataset not in EXTERNAL_DATASETS:
        raise ValueError(f"{dataset} is not a registered external dataset")
    if not path.exists():
        raise PermissionError(f"No pre-registration at {path}; the external test set stays closed")
    registration = json.loads(path.read_text(encoding="utf-8"))
    missing = [field for field in REQUIRED_FIELDS if not registration.get(field)]
    if missing:
        raise PermissionError(f"The pre-registration is missing {missing}")
    if registration["dataset"] != dataset:
        raise PermissionError(f"The pre-registration is for {registration['dataset']}, not {dataset}")
    if effective_frozen_config_a(registration) != frozen_digest():
        raise PermissionError("The pre-registration records a different frozen Config A")
    verify_config_a(config)
    return registration


def effective_frozen_config_a(registration: dict) -> str:
    """The frozen Config A identity in force: the registered one, or the latest amendment's that sets one.

    The registered fields are never rewritten. A re-freeze is recorded as an amendment carrying the new
    ``frozen_config_a``. Every amendment must be signed (``amended_by`` and ``amended_utc``) before the
    external set can be loaded, so an amendment that was drafted but not adopted keeps the data closed.
    """
    return frozen_identities(registration)["config_a"]


def frozen_identities(registration: dict) -> dict[str, str]:
    """Every configuration's frozen identity in force, from the registration and its signed amendments.

    Config A comes from ``frozen_config_a``. A later configuration is added by an amendment carrying
    ``frozen_identities`` (``{"config_b": "<identity>", ...}``). The latest amendment wins.
    """
    identities = {"config_a": registration["frozen_config_a"]}
    for number, amendment in enumerate(registration.get("amendments", []), start=1):
        unsigned = [field for field in ("amended_by", "amended_utc") if not amendment.get(field)]
        if unsigned:
            raise PermissionError(f"Amendment {amendment.get('number', number)} is not signed ({unsigned})")
        if "frozen_config_a" in amendment:
            identities["config_a"] = amendment["frozen_config_a"]
        later = amendment.get("frozen_identities", {})
        if not isinstance(later, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in later.items()):
            raise PermissionError(f"Amendment {amendment.get('number', number)}: frozen_identities must map "
                                  "configuration names to identities")
        identities.update(later)
    return identities


def opening_authorization_path(preregistration: Path) -> Path:
    return preregistration.with_name(preregistration.stem + ".opening.json")


def _utc(value: object, what: str) -> datetime:
    try:
        return datetime.strptime(str(value), _UTC).replace(tzinfo=timezone.utc)
    except ValueError:
        raise PermissionError(f"{what} is not a UTC timestamp like 2026-11-09T05:31:40Z: {value!r}") from None


def check_opening_authorization(path: Path, registration: dict) -> dict:
    """Return the Phase 5 opening authorization if it allows opening now; raise otherwise.

    ``path`` is the pre-registration; ``registration`` its validated content. Access is denied unless the
    authorization file exists and every check passes.
    """
    authorization_path = opening_authorization_path(path)
    if not authorization_path.exists():
        raise PermissionError(
            f"No Phase 5 opening authorization at {authorization_path}; signed (attested) amendments do not open "
            "the external set, and it stays closed"
        )
    auth = json.loads(authorization_path.read_text(encoding="utf-8"))
    if not isinstance(auth, dict):
        raise PermissionError("The opening authorization is not a JSON object")
    if auth.get("dataset") != registration["dataset"]:
        raise PermissionError(f"The opening authorization is for {auth.get('dataset')!r}, not {registration['dataset']}")
    if auth.get("phase") != 5:
        raise PermissionError(f"The opening authorization is for phase {auth.get('phase')!r}; opening is Phase 5 only")
    if auth.get("preregistration_sha256") != hashlib.sha256(path.read_bytes()).hexdigest():
        raise PermissionError("The opening authorization was made for a different version of the pre-registration")
    if auth.get("all_configurations_and_analyses_frozen") is not True:
        raise PermissionError("The opening authorization does not confirm that every configuration and analysis is frozen")
    conditions = auth.get("opening_conditions")
    if not isinstance(conditions, dict) or set(conditions) != set(OPENING_CONDITIONS):
        raise PermissionError(f"The opening authorization must confirm exactly the conditions {list(OPENING_CONDITIONS)}")
    unmet = [name for name in OPENING_CONDITIONS if conditions[name] is not True]
    if unmet:
        raise PermissionError(f"The opening authorization does not confirm {unmet}")

    authorized = auth.get("configurations")
    if not isinstance(authorized, dict) or "config_a" not in authorized:
        raise PermissionError("The opening authorization must list the frozen identity of every authorized "
                              "configuration, Config A included")
    recorded = frozen_identities(registration)
    for name, identity in authorized.items():
        if not isinstance(identity, str) or not _IDENTITY.fullmatch(identity):
            raise PermissionError(f"{name}: {identity!r} is not a frozen identity (16 hexadecimal characters)")
        if name not in recorded:
            raise PermissionError(f"{name} has no frozen identity recorded by signed amendment")
        if identity != recorded[name]:
            raise PermissionError(f"{name}: authorized {identity}, but the frozen identity in force is {recorded[name]}")
    if authorized["config_a"] != frozen_digest():
        raise PermissionError(f"config_a: authorized {authorized['config_a']}, but the code is {frozen_digest()}")

    if not auth.get("authorized_by") or auth["authorized_by"] != registration["registered_by"]:
        raise PermissionError(f"The opening authorization must be attested by the registered owner "
                              f"({registration['registered_by']}) in authorized_by, not {auth.get('authorized_by')!r}")
    signed = _utc(auth.get("authorized_utc"), "authorized_utc")
    earlier = [_utc(registration["registered_utc"], "registered_utc")]
    earlier += [_utc(a["amended_utc"], f"amendment {a.get('number')} amended_utc") for a in registration.get("amendments", [])]
    if signed < max(earlier):
        raise PermissionError("The opening authorization predates the registration or one of its amendments")
    if signed > datetime.now(timezone.utc):
        raise PermissionError("The opening authorization is dated in the future")
    return auth


def guarded_load(
    preregistration: str | Path,
    dataset: str,
    config: BaselineConfig,
    loader: Callable[[], T],
    purpose: str,
) -> T:
    """Check the pre-registration and the Phase 5 opening authorization, log the access, then call ``loader``."""
    path = Path(preregistration)
    entry = {
        "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": dataset,
        "purpose": purpose,
        "user": getpass.getuser(),
        "host": platform.node(),
        "preregistration_sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,
        "opening_authorization_sha256": (
            hashlib.sha256(opening_authorization_path(path).read_bytes()).hexdigest()
            if opening_authorization_path(path).exists() else None
        ),
    }
    try:
        registration = check_preregistration(path, dataset, config)
        check_opening_authorization(path, registration)
    except Exception as error:
        if path.parent.exists():
            _log(path, {**entry, "allowed": False, "reason": str(error)})
        raise
    _log(path, {**entry, "allowed": True})
    return loader()
