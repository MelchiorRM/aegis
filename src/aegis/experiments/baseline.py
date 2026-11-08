"""Run Config A: seen-family and held-out-family evaluation, plus cross-dataset tests if enabled.

    python -m aegis.experiments.baseline --config configs/baseline.yaml --out results/config_a

Each finished fold is saved on its own, so running again with the same output folder
continues where an interrupted run stopped. Seeds can also be added this way.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import gc
import json
import os
import platform
import re
import time
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
import sklearn
import torch

from aegis.config import BaselineConfig, load_config
from aegis.data.dataset import BENIGN, Dataset, remove_duplicates
from aegis.data.improved import (
    NAME as IMPROVED_KIND,
    AttemptedRows,
    DatasetWithAttempted,
    load_with_attempted,
    remove_repeated_attempted,
)
from aegis.data.loaders import dataset_files, load_dataset, project_to_shared
from aegis.data.splits import (
    Fold,
    cap_per_family,
    eligible_families,
    holdout_fold,
    make_partition,
    seen_fold,
)
from aegis.evaluation.metrics import (
    bootstrap_ci,
    evaluate_scores,
    paired_comparison,
    precision_at_prevalence,
    threshold_at_fpr,
)
from aegis.models.baseline import SCORERS, RFAEBaseline
from aegis.provenance import file_sha256, git_state, source_hash

ALL_ATTACKS = "all_attacks"
ID_COLUMNS = ["dataset", "test_dataset", "seed", "fold", "eval_family", "scorer", "target_fpr"]
HOLDOUT_PREFIX = "holdout:"


class FoldStore:
    """One CSV per finished fold. Files appear atomically, so none is ever half written."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, dataset: str, seed: int, fold: str) -> Path:
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{dataset}__seed{seed}__{fold}")
        return self.directory / f"{name}.csv"

    def done(self, dataset: str, seed: int, fold: str) -> bool:
        return self._path(dataset, seed, fold).exists()

    def save(self, dataset: str, seed: int, fold: str, rows: list[dict]) -> None:
        path = self._path(dataset, seed, fold)
        temporary = path.with_suffix(".tmp")
        pd.DataFrame(rows).to_csv(temporary, index=False)
        os.replace(temporary, path)

    def load_all(self) -> pd.DataFrame:
        return pd.concat(
            [pd.read_csv(p) for p in sorted(self.directory.glob("*.csv"))], ignore_index=True
        )


class Progress:
    """Print one line per fold, with an estimate of the time left."""

    def __init__(self, total: int, log: Callable[[str], None]) -> None:
        self.total, self.log = total, log
        self.finished, self.fitted, self.seconds = 0, 0, 0.0

    def skip(self) -> None:
        self.finished += 1

    def update(self, label: str, seconds: float) -> None:
        self.finished += 1
        self.fitted += 1
        self.seconds += seconds
        left = (self.seconds / self.fitted) * (self.total - self.finished) / 3600
        self.log(
            f"[{self.finished}/{self.total}] {label}: {seconds / 60:.1f} min; "
            f"about {left:.1f} h left at this session's average"
        )


def _hash_rows(X: pd.DataFrame) -> np.ndarray:
    return pd.util.hash_pandas_object(X, index=False).to_numpy()


@dataclasses.dataclass
class _AttemptedScores:
    """A fold's scores on the dataset's "Attempted" flows, which are benign in the secondary view."""

    scores: dict[str, np.ndarray]
    copies_training: np.ndarray  # The row's feature vector equals some training row of this fold.
    share: float  # Attempted share of all benign-view rows: n_attempted / (n_attempted + n_benign).


def _score_attempted(
    model: RFAEBaseline, ds: Dataset, train: np.ndarray, row_hashes: np.ndarray | None
) -> _AttemptedScores | None:
    """Score every attempted row; none is ever trained on, so scoring all of them leaks nothing.

    Duplicates: repeats among attempted rows were removed when the data was prepared. An attempted
    row whose features copy a training row of this fold is kept, because a deployed detector would
    see it too, and dropping it would hide the very flows where "attempted" and "attack" look alike.
    It is counted instead (``n_attempted_dup_train`` and its alarms), so its effect can be bounded.
    """
    rows: AttemptedRows | None = getattr(ds, "attempted", None)
    if rows is None or row_hashes is None:
        return None
    copies = np.isin(_hash_rows(rows.X), row_hashes[train])
    n_benign = int((ds.family == BENIGN).sum())
    return _AttemptedScores(model.scores(rows.X), copies, len(rows) / (len(rows) + n_benign))


def _attempted_columns(
    attempted: _AttemptedScores,
    scorer: str,
    threshold: float,
    metrics: dict[str, float],
    prevalences,
) -> dict[str, float]:
    """Secondary metric: attempted flows counted as benign traffic.

    Recall is unchanged by construction, since attempted rows are benign in this view and add no
    attack rows. The FPR mixes the test-benign FPR with the attempted alarm rate at the attempted
    share of the whole dataset. Adding every attempted row to the test benign rows unweighted would
    overweight them by about 1 / test_fraction, because only that share of benign rows is tested.
    """
    alarms = attempted.scores[scorer] > threshold
    rate = float(alarms.mean()) if alarms.size else float("nan")
    fpr = (1 - attempted.share) * metrics["realized_fpr"] + attempted.share * (rate if alarms.size else 0.0)
    columns = {
        "n_attempted": int(alarms.size),
        "n_attempted_dup_train": int(attempted.copies_training.sum()),
        "n_attempted_dup_train_alarms": int(alarms[attempted.copies_training].sum()),
        "attempted_share": attempted.share,
        "attempted_alarm_rate": rate,
        "realized_fpr_with_attempted": float(fpr),
    }
    for prevalence in prevalences:
        columns[f"precision_prev_{prevalence:g}_with_attempted"] = precision_at_prevalence(
            metrics["recall"], fpr, prevalence
        )
    return columns


def _score_rows(
    model: RFAEBaseline,
    fit_seconds: float,
    source: Dataset,
    target: Dataset,
    test_rows: np.ndarray,
    fold_name: str,
    eval_families: list[str],
    config: BaselineConfig,
    seed: int,
    attempted: _AttemptedScores | None = None,
) -> list[dict]:
    """Evaluate one fitted model. Thresholds come only from validation benign scores.

    With ``attempted``, each row also gets the secondary columns; without, rows are as before.
    """
    scores = model.scores(target.X.iloc[test_rows])
    families = target.family[test_rows].astype(str)
    rows = []
    for eval_family in eval_families:
        if eval_family == ALL_ATTACKS:
            mask = np.ones(len(families), dtype=bool)
        else:
            mask = np.isin(families, [BENIGN, eval_family])
        y = (families[mask] != BENIGN).astype(np.int8)
        for scorer in SCORERS:
            for target_fpr in config.target_fprs:
                threshold = threshold_at_fpr(model.val_benign_scores[scorer], target_fpr)
                metrics = evaluate_scores(
                    y, scores[scorer][mask], threshold, target_fpr, config.attack_prevalences
                )
                secondary = (
                    {}
                    if attempted is None
                    else _attempted_columns(
                        attempted, scorer, threshold, metrics, config.attack_prevalences
                    )
                )
                rows.append(
                    {
                        "dataset": source.name,
                        "test_dataset": target.name,
                        "seed": seed,
                        "fold": fold_name,
                        "eval_family": eval_family,
                        "scorer": scorer,
                        "target_fpr": target_fpr,
                        "n_attack": int(y.sum()),
                        "n_benign": int((y == 0).sum()),
                        "fit_seconds": fit_seconds,
                        **metrics,
                        **secondary,
                    }
                )
    return rows


def _run_fold(
    source: Dataset,
    target: Dataset,
    fold: Fold,
    test_rows: np.ndarray,
    eval_families: list[str],
    config: BaselineConfig,
    seed: int,
    store: FoldStore,
    progress: Progress,
    row_hashes: Callable[[], np.ndarray] | None = None,
) -> None:
    """``row_hashes`` gives the source rows' feature hashes, needed only for attempted rows."""
    if store.done(source.name, seed, fold.name):
        progress.skip()
        return
    start = time.perf_counter()
    model = RFAEBaseline(config.rf, config.autoencoder, seed).fit(
        source.X.iloc[fold.train],
        source.y[fold.train],
        source.X.iloc[fold.val],
        source.y[fold.val],
        source.numeric,
        source.categorical,
    )
    fit_seconds = time.perf_counter() - start
    attempted = None
    if source is target and getattr(target, "attempted", None) is not None:
        attempted = _score_attempted(model, target, fold.train, row_hashes() if row_hashes else None)
    rows = _score_rows(
        model, fit_seconds, source, target, test_rows, fold.name, eval_families, config, seed, attempted
    )
    store.save(source.name, seed, fold.name, rows)
    progress.update(f"seed {seed} {source.name} {fold.name}", time.perf_counter() - start)
    del model
    gc.collect()


def evaluate_within_dataset(
    ds: Dataset, config: BaselineConfig, seed: int, store: FoldStore, progress: Progress
) -> None:
    partition = make_partition(ds.family, seed, config.val_fraction, config.test_fraction)
    families = eligible_families(ds.family, config.min_family_count)
    if not families:
        raise ValueError(f"{ds.name}: no family reaches min_family_count={config.min_family_count}")

    cache: list[np.ndarray] = []

    def row_hashes() -> np.ndarray:  # Hashed once, and only if a fold with attempted rows runs.
        if not cache:
            cache.append(_hash_rows(ds.X))
        return cache[0]

    fold = seen_fold(partition, ds.family, config.max_train_per_family, seed)
    _run_fold(
        ds, ds, fold, fold.test, [ALL_ATTACKS, *families], config, seed, store, progress, row_hashes
    )
    for family in families:
        fold = holdout_fold(partition, ds.family, family, config.max_train_per_family, seed)
        _run_fold(ds, ds, fold, fold.test, [family], config, seed, store, progress, row_hashes)


def evaluate_cross_dataset(
    source: Dataset,
    target: Dataset,
    config: BaselineConfig,
    seed: int,
    store: FoldStore,
    progress: Progress,
) -> None:
    """Train and calibrate on one dataset, then test on every row of the other."""
    partition = make_partition(source.family, seed, config.val_fraction, config.test_fraction)
    train = cap_per_family(partition.train, source.family, config.max_train_per_family, seed)
    fold = Fold(f"cross:{source.name}->{target.name}", train, partition.val, partition.test)
    rows = np.arange(len(target.X))
    _run_fold(source, target, fold, rows, [ALL_ATTACKS], config, seed, store, progress)


def summarize(results: pd.DataFrame, samples: int) -> pd.DataFrame:
    """Mean and bootstrap interval across seeds for each metric."""
    group = ["dataset", "test_dataset", "fold", "eval_family", "scorer", "target_fpr"]
    metrics = [c for c in results.columns if c not in ID_COLUMNS and not c.startswith("n_")]
    rows = []
    for key, part in results.groupby(group, sort=True):
        row = dict(zip(group, key), n_seeds=part["seed"].nunique())
        for metric in metrics:
            low, high = bootstrap_ci(part[metric].to_numpy(), samples=samples)
            row[f"{metric}_mean"] = float(part[metric].mean())
            row[f"{metric}_ci_low"], row[f"{metric}_ci_high"] = low, high
        rows.append(row)
    return pd.DataFrame(rows)


def degradation(results: pd.DataFrame, samples: int) -> pd.DataFrame:
    """RQ1 reference: recall lost on the same test flows once a family is held out."""
    keys = ["dataset", "eval_family", "scorer", "target_fpr"]
    within = results[results["dataset"] == results["test_dataset"]]
    seen = within[(within["fold"] == "seen") & (within["eval_family"] != ALL_ATTACKS)]
    held = within[within["fold"].str.startswith(HOLDOUT_PREFIX)]
    merged = seen.merge(held, on=[*keys, "seed"], suffixes=("_seen", "_heldout"))
    rows = []
    for key, part in merged.groupby(keys, sort=True):
        rows.append(
            {
                **dict(zip(keys, key)),
                "recall_seen_mean": float(part["recall_seen"].mean()),
                "recall_heldout_mean": float(part["recall_heldout"].mean()),
                **paired_comparison(
                    part["recall_seen"].to_numpy(), part["recall_heldout"].to_numpy(), samples=samples
                ),
            }
        )
    return pd.DataFrame(rows)


def phase1_gate(results: pd.DataFrame, datasets: list[Dataset], config: BaselineConfig) -> pd.DataFrame:
    """Roadmap gate for phase 1: Config A measured on every eligible held-out family."""
    rows = []
    for ds in datasets:
        for family in eligible_families(ds.family, config.min_family_count):
            part = results[
                (results["dataset"] == ds.name)
                & (results["test_dataset"] == ds.name)
                & (results["fold"] == f"{HOLDOUT_PREFIX}{family}")
                & (results["eval_family"] == family)
            ]
            measured = sorted(int(s) for s in part["seed"].unique() if s in config.seeds)
            rows.append(
                {
                    "dataset": ds.name,
                    "family": family,
                    "seeds_measured": len(measured),
                    "seeds_required": len(config.seeds),
                    "complete": len(measured) == len(config.seeds),
                }
            )
    return pd.DataFrame(rows)


def prepare_datasets(config: BaselineConfig) -> tuple[list[Dataset], dict[str, dict[str, int]]]:
    """Load and clean every configured dataset, returning the cleaning counts too.

    The improved CICIDS2017 comes back as a ``DatasetWithAttempted``: the primary rows cleaned as
    usual, plus its "Attempted" flows (repeats removed) for the secondary metric. Its cleaning
    counts gain the attempted row counts; other datasets are unchanged.
    """
    datasets, cleaning = [], {}
    for dataset_config in config.datasets:
        if dataset_config.kind == IMPROVED_KIND:
            if dataset_config.path is None:
                raise ValueError(f"Dataset {dataset_config.kind} needs a path")
            loaded, attempted = load_with_attempted(dataset_config.path, dataset_config.drop_columns)
            cleaned, stats = remove_duplicates(loaded)
            del loaded
            attempted, attempted_stats = remove_repeated_attempted(attempted)
            cleaned = DatasetWithAttempted(
                cleaned.name, cleaned.X, cleaned.family, cleaned.categorical, attempted
            )
            stats = {**stats, **attempted_stats}
        else:
            cleaned, stats = remove_duplicates(load_dataset(dataset_config))
        datasets.append(cleaned)
        cleaning[cleaned.name] = stats
    return datasets, cleaning


def _experiment_settings(config: BaselineConfig) -> dict:
    """Settings that define the experiment, leaving out what describes the machine.

    Seeds and the cross-dataset switch only add folds. Worker count, device and data
    location can change when a session moves to another runtime.
    """
    settings = dataclasses.asdict(config)
    for key in ("seeds", "cross_dataset"):
        settings.pop(key)
    settings["rf"].pop("n_jobs")
    settings["autoencoder"].pop("device")
    for dataset in settings["datasets"]:
        dataset.pop("path")
    return settings


def _source_checksums(config: BaselineConfig) -> dict[str, dict[str, str]]:
    """SHA-256 of each source CSV, read once per session whether or not folds remain."""
    checksums = {}
    for dataset in config.datasets:
        files = dataset_files(dataset)
        if files:
            checksums[dataset.name or dataset.kind] = {p.name: file_sha256(p) for p in files}
    return checksums


def _write_manifest(
    out: Path,
    config: BaselineConfig,
    datasets: list[Dataset],
    cleaning: dict,
    extra: dict | None,
    log: Callable[[str], None],
) -> None:
    """Record what produced the results, and refuse to mix incomparable runs.

    The identity covers the settings, package source and data contents, since a change to
    any of them makes saved folds incomparable with new ones. Source checksums are part of
    it because counts cannot see a release that changes values but not row counts. Files
    are identified by name and content, not location, so a moved folder still resumes.
    Each session's machine details are logged, because GPU and CPU autoencoder training
    can differ numerically.
    """
    family_counts = {d.name: d.family_counts() for d in datasets}
    identity = json.loads(
        json.dumps(
            {
                "settings": _experiment_settings(config),
                "source_version": source_hash(),
                "data": {
                    "cleaning": cleaning,
                    "family_counts": family_counts,
                    "source_sha256": _source_checksums(config),
                },
                "extra": extra or {},
            }
        )
    )

    sessions: list[dict] = []
    path = out / "manifest.json"
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            previous_identity, sessions = previous["identity"], previous["sessions"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError(
                f"{path} is unreadable or from an older version of Aegis, so its results "
                "cannot be checked for comparability. Use a new output folder."
            ) from error
        if previous_identity != identity:
            raise ValueError(
                f"{out} holds results from different settings, code or data. "
                "Use a new output folder."
            )
    device = config.autoencoder.device
    if sessions and sessions[-1]["ae_device"] != device:
        log(
            f"NOTE: autoencoder device changed from {sessions[-1]['ae_device']} to {device}. "
            "Saved folds are kept, and manifest.json records each session's device."
        )
    sessions.append(
        {
            "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "folds_already_done": len(list((out / "folds").glob("*.csv"))),
            "ae_device": device,
            "rf_n_jobs": config.rf.n_jobs,
            "dataset_paths": {d.name or d.kind: d.path for d in config.datasets},
            "git": git_state(),
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "torch": torch.__version__,
        }
    )
    path.write_text(
        json.dumps(
            {
                "identity": identity,
                "seeds": list(config.seeds),
                "cross_dataset": config.cross_dataset,
                "sessions": sessions,
                "cleaning": cleaning,
                "family_counts": family_counts,
                "held_out_families": {
                    d.name: eligible_families(d.family, config.min_family_count) for d in datasets
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def run(
    config: BaselineConfig,
    out: str | Path,
    prepared: tuple[list[Dataset], dict] | None = None,
    extra_manifest: dict | None = None,
    log: Callable[[str], None] = print,
) -> pd.DataFrame:
    """Run or continue an experiment, then write the combined result files."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    datasets, cleaning = prepared if prepared is not None else prepare_datasets(config)
    _write_manifest(out, config, datasets, cleaning, extra_manifest, log)
    store = FoldStore(out / "folds")

    cross = config.cross_dataset and len(datasets) >= 2
    within_folds = sum(
        1 + len(eligible_families(d.family, config.min_family_count)) for d in datasets
    )
    cross_folds = len(datasets) * (len(datasets) - 1) if cross else 0
    progress = Progress((within_folds + cross_folds) * len(config.seeds), log)

    for seed in config.seeds:
        for ds in datasets:
            evaluate_within_dataset(ds, config, seed, store, progress)

    if cross:
        shared = [remove_duplicates(project_to_shared(d))[0] for d in datasets]
        for seed in config.seeds:
            for source in shared:
                for target in shared:
                    if source.name != target.name:
                        evaluate_cross_dataset(source, target, config, seed, store, progress)

    results = store.load_all()
    results = results[results["seed"].isin(config.seeds)].reset_index(drop=True)
    results.to_csv(out / "results.csv", index=False)
    summarize(results, config.bootstrap_samples).to_csv(out / "summary.csv", index=False)
    degradation(results, config.bootstrap_samples).to_csv(out / "degradation.csv", index=False)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    run(load_config(args.config), args.out)
    print(f"Results written to {args.out}")


if __name__ == "__main__":
    main()
