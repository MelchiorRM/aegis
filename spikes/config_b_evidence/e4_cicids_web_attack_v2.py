"""Evidence step E4, run 2 (corrected; owner approval 2026-11-09, one controlled rerun): composition of improved CICIDS2017 `web_attack` training rows by raw
label. Approved procedure: docs/config-b-mapping-draft.md, section 5. Read-only.

- Loads the primary rows with Config A's own loader (`load_with_attempted`) and cleaning (`remove_duplicates`),
  exactly as `prepare_datasets` does. That code parses and hashes every column; this script reads no numeric value.
- Separately reads only the `Label` and `Attempted Category` columns of the same day files, with the same row
  filter as Config A's reader (rows with a `Label`, non-Attempted rows), and carries the raw label through
  Config A's cleaning by the kept row index.
- Correction over run 1 (results/config_b_evidence/e4_failed_run_1): `Dataset` resets its row index, so the
  cleaned index cannot locate kept rows. The kept-row mask is computed with the same expression as
  `aegis.data.dataset.remove_duplicates` and is used only after it reproduces Config A's cleaned output exactly:
  row count, family array, and the row hash of every kept feature row.
- Alignment check: the carried raw labels, mapped through `aegis.data.improved.FAMILIES`, must equal Config A's
  family array row for row, before and after cleaning, and the cleaned counts must equal Config A's manifest.
  Any mismatch stops the step.
- Selects the seed-0 training partition and asserts it is disjoint from that partition's, and every held-out
  fold's, validation and test rows. Writes only aggregate counts. Fits nothing and scores nothing.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from aegis.config import load_config
from aegis.data.dataset import remove_duplicates
from aegis.data.improved import ATTEMPTED_COLUMN, FAMILIES, day_files, load_with_attempted, parse_labels
from aegis.data.splits import eligible_families, holdout_fold, make_partition

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "config_b_evidence" / "e4_run_2"
MANIFEST = ROOT / "results" / "config_a_improved_25685b84dd83f65c" / "manifest.json"
SEED = 0
FAMILY = "web_attack"
SQLI_FLOOR = 20  # Fixed before running: below this, the report says the mapping replays mostly other web attacks.


def stop(message: str) -> None:
    raise SystemExit(f"STOP: {message}")


def frozen_check() -> str:
    out = subprocess.run([sys.executable, "-m", "aegis.frozen"], cwd=ROOT, capture_output=True, text=True)
    text = (out.stdout + out.stderr).strip()
    if "Matches the frozen Config A" not in text:
        stop(f"Config A identity check failed: {text}")
    return text.splitlines()[-1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def raw_labels(directory: Path) -> np.ndarray:
    """Raw labels of the primary (non-Attempted) rows, in Config A's row order."""
    parts = []
    for path in day_files(directory):
        frame = pd.read_csv(path, encoding="latin-1", low_memory=False, usecols=lambda c: c.strip() in
                            ("Label", ATTEMPTED_COLUMN))
        frame.columns = frame.columns.str.strip()
        frame = frame.dropna(subset=["Label"])  # The same filter as aegis.data.improved._read.
        _, attempted = parse_labels(frame["Label"], frame[ATTEMPTED_COLUMN], path.name)
        parts.append(frame["Label"].astype(str).str.strip().to_numpy(dtype=object)[~attempted])
    return np.concatenate(parts)


def to_family(raw: np.ndarray) -> np.ndarray:
    return pd.Series(raw).str.lower().map(FAMILIES).to_numpy(dtype=object)


def kept_mask(ds) -> tuple[np.ndarray, np.ndarray]:
    """The keep mask of aegis.data.dataset.remove_duplicates (same expression), and every row's hash."""
    hashes = pd.util.hash_pandas_object(ds.X, index=False).to_numpy()
    keys = pd.DataFrame({"hash": hashes, "family": ds.family.astype(str)})
    conflicting = keys.groupby("hash")["family"].transform("nunique").to_numpy() > 1
    repeated = keys.duplicated("hash").to_numpy()
    return ~conflicting & ~repeated, hashes


def main() -> None:
    before = frozen_check()
    config = load_config(ROOT / "configs" / "baseline.yaml")
    (improved,) = [d for d in config.datasets if d.kind == "cicids2017_improved"]
    directory = ROOT / improved.path
    files = {p.name: sha256(p) for p in day_files(directory)}
    recorded = json.loads(MANIFEST.read_text())["identity"]["data"]

    primary, _ = load_with_attempted(directory, improved.drop_columns)
    raw = raw_labels(directory)
    if len(raw) != len(primary.family) or not np.array_equal(to_family(raw), primary.family.astype(object)):
        stop("raw labels do not reproduce Config A's families before cleaning")
    cleaned, cleaning = remove_duplicates(primary)  # Config A's cleaning: the reference.
    keep, hashes = kept_mask(primary)
    del primary
    # Verify the mask against Config A's cleaned output before using it.
    if int(keep.sum()) != len(cleaned.family):
        stop(f"mask keeps {int(keep.sum())} rows; Config A's cleaning kept {len(cleaned.family)}")
    if not np.array_equal(to_family(raw)[keep], cleaned.family.astype(object)):
        stop("mask does not reproduce Config A's cleaned family array")
    if not np.array_equal(hashes[keep], pd.util.hash_pandas_object(cleaned.X, index=False).to_numpy()):
        stop("mask does not reproduce Config A's cleaned rows (row hashes differ)")
    raw = raw[keep]
    if not np.array_equal(to_family(raw), cleaned.family.astype(object)):
        stop("raw labels do not reproduce Config A's families after cleaning")
    if cleaning["rows_after"] != recorded["cleaning"]["cicids2017_improved"]["rows_after"]:
        stop(f"cleaned row count {cleaning['rows_after']} differs from Config A's manifest")
    counts = pd.Series(cleaned.family.astype(str)).value_counts().to_dict()
    if counts != recorded["family_counts"]["cicids2017_improved"]:
        stop("cleaned family counts differ from Config A's manifest")

    partition = make_partition(cleaned.family, SEED, config.val_fraction, config.test_fraction)
    labels = cleaned.family.astype(str)
    selected = partition.train[labels[partition.train] == FAMILY]
    if len(selected) == 0:
        stop("no web_attack rows selected")
    if np.intersect1d(selected, partition.val).size or np.intersect1d(selected, partition.test).size:
        stop("selected rows overlap the partition's validation or test rows")
    folds_checked = []
    for held in eligible_families(cleaned.family, config.min_family_count):
        fold = holdout_fold(partition, cleaned.family, held, config.max_train_per_family, SEED)
        if np.intersect1d(selected, fold.val).size or np.intersect1d(selected, fold.test).size:
            stop(f"selected rows overlap validation or test rows of fold holdout:{held}")
        folds_checked.append(held)

    table = pd.Series(raw[selected]).value_counts().rename("rows").to_frame()
    table["share"] = table["rows"] / len(selected)
    OUT.mkdir(parents=True, exist_ok=True)
    table.to_csv(OUT / "web_attack_train_seed0_by_label.csv")
    sqli = int(table["rows"][table.index.str.lower().str.contains("sql injection")].sum())
    after = frozen_check()
    manifest = {
        "step": "E4", "seed": SEED, "family": FAMILY, "rows_selected": int(len(selected)),
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
        "frozen_before": before, "frozen_after": after, "dataset_sha256": files, "cleaning": cleaning,
        "run": 2, "failed_run_preserved": "results/config_b_evidence/e4_failed_run_1",
        "alignment": {"families_reproduced_before_cleaning": True, "mask_row_count_matches": True,
                      "mask_families_match": True, "mask_row_hashes_match": True,
                      "families_reproduced_after_cleaning": True,
                      "rows_after_matches_manifest": True, "family_counts_match_manifest": True},
        "assertions": {"disjoint_from_partition_val_test": True, "disjoint_from_holdout_folds_val_test": folds_checked},
        "columns_read": ["Label", ATTEMPTED_COLUMN],
        "sql_injection_training_rows": sqli, "sqli_floor": SQLI_FLOOR,
        "replays_mostly_other_web_attacks": sqli < SQLI_FLOOR,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    print(f"\nweb_attack, seed-0 training partition\n{table.to_string()}")


if __name__ == "__main__":
    main()
