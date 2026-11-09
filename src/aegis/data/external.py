"""The only way to load an external test set, so it is touched once and on the record.

An external dataset is loaded through ``guarded_load``. It refuses unless a pre-registration file
exists, names this dataset, has every required field and only signed amendments, and records (directly
or through its latest amendment) the frozen Config A identity that the current configuration and code
still match. Every attempt, refused or not, is appended to an
access log beside the pre-registration file.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import platform
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
    identity = registration["frozen_config_a"]
    for number, amendment in enumerate(registration.get("amendments", []), start=1):
        unsigned = [field for field in ("amended_by", "amended_utc") if not amendment.get(field)]
        if unsigned:
            raise PermissionError(f"Amendment {amendment.get('number', number)} is not signed ({unsigned})")
        identity = amendment.get("frozen_config_a", identity)
    return identity


def guarded_load(
    preregistration: str | Path,
    dataset: str,
    config: BaselineConfig,
    loader: Callable[[], T],
    purpose: str,
) -> T:
    """Check the pre-registration, log the access, then call ``loader``."""
    path = Path(preregistration)
    entry = {
        "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": dataset,
        "purpose": purpose,
        "user": getpass.getuser(),
        "host": platform.node(),
        "preregistration_sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,
    }
    try:
        check_preregistration(path, dataset, config)
    except Exception as error:
        if path.parent.exists():
            _log(path, {**entry, "allowed": False, "reason": str(error)})
        raise
    _log(path, {**entry, "allowed": True})
    return loader()
