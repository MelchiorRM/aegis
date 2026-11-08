"""The frozen Config A identity: what may be called the Config A baseline from Phase 1 on.

It covers the settings that define the experiment and the source files that implement the baseline:
loading, cleaning, splitting, the Random Forest score and the threshold rule. Machine details (worker
count, device, data location) are left out. Changing any of these is a new baseline, and needs an
explicit re-freeze with a reason.

    python -m aegis.frozen           # show the current identity and whether it matches
    python -m aegis.frozen --write   # re-freeze; only with a recorded reason
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import pprint
import re
from pathlib import Path

from aegis.config import BaselineConfig, load_config
from aegis.provenance import PACKAGE_DIR

SCORER = "rf"
THRESHOLD_RULE = "validation benign scores, quantile 1 - target_fpr, method higher"
IMPLEMENTATION = (
    "data/dataset.py", "data/improved.py", "data/loaders.py", "data/splits.py", "evaluation/metrics.py",
    "models/baseline.py",
)

# BEGIN FROZEN
FROZEN = {'scorer': 'rf',
 'threshold_rule': 'validation benign scores, quantile 1 - target_fpr, method higher',
 'settings': {'datasets': [{'kind': 'cicids2017_improved',
                            'name': None,
                            'seed': 0,
                            'drop_columns': ['Dst Port']},
                           {'kind': 'unsw_nb15', 'name': None, 'seed': 0, 'drop_columns': []}],
              'val_fraction': 0.2,
              'test_fraction': 0.2,
              'max_train_per_family': 100000,
              'min_family_count': 200,
              'target_fprs': [0.01, 0.001],
              'attack_prevalences': [0.01, 0.001],
              'bootstrap_samples': 10000,
              'rf': {'n_estimators': 100, 'max_depth': 20, 'min_samples_leaf': 2}},
 'implementation_sha256': {'data/dataset.py': 'fdb123bdbb6d1bca86abbe4ab27751aa0fe95dc9f6f23cf57e309e8d2ec2a3e7',
                           'data/improved.py': 'e4afcc06babca0edb8472b1ae385d3eb8f7fa72107c87465d27f3bb0046d3435',
                           'data/loaders.py': 'd8294e7873f113827e5bb14fe7a42d124076bb0197cfdf55d688ca0f81799f94',
                           'data/splits.py': '2836ea104a746428113c87b7305e988662e2be5c65e22f92ac2260e15563b097',
                           'evaluation/metrics.py': '09665b94a4a31c1c2ba6d8afba7085ae0552748be346f237513e60159ea65013',
                           'models/baseline.py': '9ad60689d7e836271eaa4dad1b639b7d4f8d34f4307a5c088eaa82972bbdbffa'}}
# END FROZEN


def _normalized(text: str) -> str:
    return text.replace("\r\n", "\n")


def current_identity(config: BaselineConfig) -> dict:
    settings = dataclasses.asdict(config)
    settings.pop("cross_dataset")
    settings.pop("seeds")  # Seeds only add folds; adding them does not change the baseline.
    settings.pop("autoencoder")  # The baseline is the rf score; the autoencoder is not part of it.
    settings["rf"].pop("n_jobs")
    for dataset in settings["datasets"]:
        dataset.pop("path")
    files = {
        name: hashlib.sha256(_normalized((PACKAGE_DIR / name).read_text(encoding="utf-8")).encode()).hexdigest()
        for name in IMPLEMENTATION
    }
    return json.loads(json.dumps(
        {"scorer": SCORER, "threshold_rule": THRESHOLD_RULE, "settings": settings, "implementation_sha256": files}
    ))


def frozen_digest() -> str:
    """A short fingerprint of the frozen identity, for pre-registration files."""
    if not FROZEN:
        raise RuntimeError("Config A has not been frozen")
    return hashlib.sha256(json.dumps(FROZEN, sort_keys=True).encode()).hexdigest()[:16]


def differences(config: BaselineConfig) -> list[str]:
    if not FROZEN:
        return ["Config A has not been frozen"]
    now = current_identity(config)
    found = []

    def walk(old, new, where):
        if isinstance(old, dict) and isinstance(new, dict):
            for key in sorted(set(old) | set(new)):
                walk(old.get(key), new.get(key), f"{where}.{key}" if where else key)
        elif old != new:
            found.append(f"{where}: frozen {old!r}, now {new!r}")

    walk(FROZEN, now, "")
    return found


def verify_config_a(config: BaselineConfig) -> None:
    """Refuse to treat this configuration and code as Config A unless they match the frozen identity."""
    found = differences(config)
    if found:
        raise ValueError("Not the frozen Config A:\n  " + "\n  ".join(found))


def write_frozen(config: BaselineConfig, path: Path = Path(__file__)) -> None:
    text = path.read_text(encoding="utf-8")
    literal = pprint.pformat(current_identity(config), sort_dicts=False, width=100)
    block = "# BEGIN FROZEN\nFROZEN = " + literal + "\n# END FROZEN"
    path.write_text(re.sub(r"# BEGIN FROZEN\n.*?# END FROZEN", lambda _: block, text, flags=re.S), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/baseline.yaml")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    if args.write:
        write_frozen(config)
        print("Frozen.")
        return
    found = differences(config)
    print("Matches the frozen Config A" if not found else "\n".join(found))


if __name__ == "__main__":
    main()
