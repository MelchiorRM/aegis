"""Config B stages 1-5 (sections 6-12), run one stage at a time under the stop rules.

    python -m aegis.config_b.experiment --stage 1 --out results/config_b

Every stage refuses to start unless all of these hold:
- the frozen Config A identity matches;
- the amendment is registered;
- the Config B identity equals the one in the signed identity addendum;
- every Config B amendment is signed;
- the stage is authorized by the owner in ``config_b.json``;
- the bank passes its pre-run check;
- the compute projection is within the approved budget.

Evaluation reuses Config A's helpers unchanged: treatments, raw-row views, metrics, and selection's
``pair_rows`` and ``select``. Each fold's rows match the artifact audit's ``_fold_rows`` columns, with the arm,
ratio and replay accounting added.
"""

from __future__ import annotations

import argparse
import gc
import itertools
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from aegis.config import BaselineConfig, load_config
from aegis.config_b import analysis, protocol
from aegis.config_b.compute import Ledger, StopRun
from aegis.config_b.model import (
    FingerprintRegistry, InvariantViolation, ReplayForest, check_replay_rows, check_settings,
    preprocessing_fingerprint, preprocessing_gate,
)
from aegis.config_b.replay import accounting, allocate_b, replay_for
from aegis.data.dataset import BENIGN, Dataset, remove_duplicates
from aegis.data.loaders import load_dataset
from aegis.data.splits import Fold, Partition, eligible_families, holdout_fold, make_partition, seen_fold
from aegis.evaluation.metrics import evaluate_scores, threshold_at_fpr
from aegis.experiments.artifacts import (
    RawRows, Treatment, _rows_hash, build_raw_rows, evaluate_raw, missingness_frame, signatures, training_rows,
    treat_frame, treated_features, treatments_for,
)
from aegis.experiments.baseline import FoldStore
from aegis.experiments.selection import pair_rows, select

# Section 12 as amended by the proposed Config B amendment 1 (G2): stage 1 fits arm A only.
STAGE_WORK = {
    "1": "A outer folds, seed 0 (calibration)",
    "2a": "nested selection of B",
    "2b": "nested selection of B0",
    "3": "outer folds: A seeds 1-4; B and B0 seeds 0-4 at their selected ratios",
    "4a": "shortcut audit of B", "4b": "shortcut audit of B0", "4c": "shortcut audit of A",
    "5": "determinism rerun of every outer fold",
}
SEEN_FOLD_CANDIDATE = protocol.CANDIDATES[0]  # Proposed amendment 1 (G1): the seen fold uses the default 0.25.


@dataclass
class Prepared:
    ds: Dataset
    raw_rows: RawRows
    flow_signatures: np.ndarray
    flows: np.ndarray
    indicators: pd.DataFrame
    plan: dict[str, Treatment]
    families: list[str]
    cleaning: dict


def prepare(config: BaselineConfig, raw: Dataset | None = None, families=protocol.HELD_OUT_FAMILIES,
            required_treatments=(protocol.REFERENCE, *protocol.RULE_TREATMENTS, *protocol.OUTSIDE_RULE)) -> Prepared:
    """Load and clean the dataset as Config A does, and build the raw-row views of the artifact audit."""
    if raw is None:
        chosen = [d for d in config.datasets if d.kind == protocol.DATASET]
        if len(chosen) != 1:
            raise ValueError(f"the configuration must list {protocol.DATASET} exactly once (Scope A)")
        raw = load_dataset(chosen[0])
    raw_rows = build_raw_rows(raw)
    clean, stats = remove_duplicates(raw)
    raw_rows.indicators = missingness_frame(
        Dataset(clean.name, raw_rows.X, raw_rows.family, clean.categorical)
    ).reindex(columns=missingness_frame(clean).columns, fill_value=0.0)
    found = eligible_families(clean.family, config.min_family_count)
    if tuple(found) != tuple(families):
        raise ValueError(f"eligible families {found} are not the registered {list(families)}")
    plan = {t.name: t for t in treatments_for(clean)}
    missing = set(required_treatments) - set(plan)
    if missing:
        raise ValueError(f"{clean.name} lacks the registered treatments {sorted(missing)}")
    return Prepared(clean, raw_rows, signatures(clean), pd.util.hash_pandas_object(clean.X, index=False).to_numpy(),
                    missingness_frame(clean), plan, found, stats)


class Runner:
    """Shared state of one results folder: stores, the fingerprint registry, the ledger and the bank events."""

    def __init__(self, prep: Prepared, config: BaselineConfig, out: Path, events: dict[int, dict[str, int]],
                 ledger: Ledger, log: Callable[[str], None] = print) -> None:
        self.prep, self.config, self.out, self.events, self.ledger, self.log = prep, config, out, events, ledger, log
        out.mkdir(parents=True, exist_ok=True)
        self.folds = FoldStore(out / "folds")
        self.inner = FoldStore(out / "selection")
        self.rerun = FoldStore(out / "determinism")
        self.accounting_dir = out / "accounting"
        self.accounting_dir.mkdir(exist_ok=True)
        self.registry = FingerprintRegistry(out / "preprocessing_fingerprints.json")
        self.gate_pending = False
        self.stage = ""

    # ----- one fit -----
    def _fit(self, *, arm: str, train: np.ndarray, config_a_train: np.ndarray, replay, expected_total: int,
             excluded: dict, test: np.ndarray | None, held_out: set[str], seed: int, treatment: Treatment,
             val_benign: np.ndarray, context: str) -> ReplayForest:
        ds = self.prep.ds
        positions = check_replay_rows(
            arm=arm, train=train, config_a_train=config_a_train, copies=replay.copies, expected_total=expected_total,
            excluded={**excluded, "held-out family": np.flatnonzero(np.isin(ds.family.astype(str), list(held_out)))},
            flows=self.prep.flows, test=test,
        )
        check_settings(self.config.rf, seed, seed)
        frame = treated_features(ds, treatment, train, self.prep.indicators)
        categorical = [c for c in ds.categorical if c in frame.columns] if not treatment.missingness_only else []
        numeric = [c for c in frame.columns if c not in categorical]
        val_frame = treated_features(ds, treatment, val_benign, self.prep.indicators)
        model = ReplayForest(self.config.rf, seed).preprocess(frame, numeric, categorical)
        self.registry.check(context, preprocessing_fingerprint(model.preprocessor, model.distinct))  # Invariant 3.
        if self.gate_pending:  # Invariant 6, before the first forest of the stage.
            preprocessing_gate(model, frame, ds.y[train], val_frame, numeric, categorical)
            self.gate_pending = False
        return model.fit_forest(ds.y[train], positions, val_frame)

    # ----- outer and audit folds -----
    def evaluate(self, arm: str, fold: Fold, partition: Partition, treatment: Treatment, seed: int,
                 candidate: str) -> tuple[list[dict], dict]:
        ds, prep = self.prep.ds, self.prep
        ratio = float(candidate) if arm != "A" else 0.0
        train = training_rows(fold, ds, treatment, prep.flow_signatures)  # Config A's rows for this treatment.
        events = self.events[seed]
        replay = replay_for(arm, train, ds.family, events, ratio, seed)
        expected = 0 if arm == "A" else allocate_b(train, ds.family, events, ratio, seed).total
        labels = ds.family.astype(str)
        uncapped = partition.train if fold.held_out is None else partition.train[labels[partition.train] != fold.held_out]
        val_benign = fold.val[labels[fold.val] == BENIGN]
        name = "seen" if fold.held_out is None else "holdout"
        with self.ledger.fit(self.stage, f"{arm}:{treatment.name}:{fold.name}:seed{seed}"):  # Fit and scoring.
            return self._evaluate(arm, fold, partition, treatment, seed, ratio, train, replay, expected, uncapped,
                                  val_benign, name)

    def _evaluate(self, arm, fold, partition, treatment, seed, ratio, train, replay, expected, uncapped, val_benign,
                  name) -> tuple[list[dict], dict]:
        ds, prep = self.prep.ds, self.prep
        labels = ds.family.astype(str)
        model = self._fit(
            arm=arm, train=train, config_a_train=train, replay=replay, expected_total=expected,
            excluded={"validation": partition.val, "test": partition.test,
                      "cap-excluded": np.setdiff1d(uncapped, fold.train)},
            test=fold.test, held_out={fold.held_out} if fold.held_out else set(), seed=seed, treatment=treatment,
            val_benign=val_benign, context=f"seed{seed}:{fold.name}:{treatment.name}",
        )
        info = accounting(train, ds.family, replay)
        families = [fold.held_out] if fold.held_out else prep.families
        scores_test = model.scores(treated_features(ds, treatment, fold.test, prep.indicators))
        test_benign_flows = prep.flows[fold.test[labels[fold.test] == BENIGN]]
        raw_family = prep.raw_rows.family.astype(str)
        benign = (raw_family == BENIGN) & (prep.raw_rows.conflicting | np.isin(prep.raw_rows.flow, test_benign_flows))
        benign_scores = model.scores(treat_frame(prep.raw_rows.X[benign], treatment, prep.raw_rows.indicators[benign]))
        rows = []
        for family in families:
            keep = np.isin(labels[fold.test], [BENIGN, family])
            test_rows, scores = fold.test[keep], scores_test[keep]
            y = (labels[test_rows] != BENIGN).astype(np.int8)
            attack = raw_family == family
            attack_scores = model.scores(treat_frame(prep.raw_rows.X[attack], treatment, prep.raw_rows.indicators[attack]))
            for target_fpr in self.config.target_fprs:
                threshold = threshold_at_fpr(model.val_benign_scores, target_fpr)
                rows.append({
                    "dataset": ds.name, "arm": arm, "seed": seed, "fold": name, "treatment": treatment.name,
                    "family": family, "target_fpr": target_fpr, "ratio": ratio,
                    "fold_group": "seen" if fold.held_out is None else protocol.fold_group(family),
                    "train_rows": int(len(train)), "replay_total": replay.total, "fit_rows": model.n_fit_rows,
                    "attack_ess": info["attack_class"]["ess"], "n_attack": int(y.sum()), "n_benign": int((y == 0).sum()),
                    "auc": float(roc_auc_score(y, scores)),
                    **evaluate_scores(y, scores, threshold, target_fpr, self.config.attack_prevalences),
                    **evaluate_raw(model, prep.raw_rows, target_fpr, attack_scores, benign_scores, attack, benign),
                    "attack_rows_hash": _rows_hash(test_rows[y == 1], np.flatnonzero(attack)),
                    "benign_rows_hash": _rows_hash(test_rows[y == 0], np.flatnonzero(benign)),
                })
        return rows, info

    def outer(self, arm: str, seed: int, candidates: dict[str | None, str], store: FoldStore) -> None:
        """The seen fold and every held-out fold of one arm and seed, reference treatment only."""
        ds = self.prep.ds
        partition = make_partition(ds.family, seed, self.config.val_fraction, self.config.test_fraction)
        cap = self.config.max_train_per_family
        folds = [seen_fold(partition, ds.family, cap, seed)] + [
            holdout_fold(partition, ds.family, f, cap, seed) for f in self.prep.families]
        for fold in folds:
            label = f"{arm}:{protocol.REFERENCE}:{fold.name}"
            if store.done(ds.name, seed, label):
                continue
            rows, info = self.evaluate(arm, fold, partition, self.prep.plan[protocol.REFERENCE], seed,
                                       candidates[fold.held_out])
            self._save(store, seed, label, rows, info)

    def audit(self, arm: str, seed: int, candidates: dict[str | None, str]) -> None:
        ds = self.prep.ds
        partition = make_partition(ds.family, seed, self.config.val_fraction, self.config.test_fraction)
        for family in self.prep.families:
            fold = holdout_fold(partition, ds.family, family, self.config.max_train_per_family, seed)
            for name in (*protocol.RULE_TREATMENTS, *protocol.OUTSIDE_RULE):
                if name not in self.prep.plan:
                    continue
                label = f"{arm}:{name}:{fold.name}"
                if self.folds.done(ds.name, seed, label):
                    continue
                rows, info = self.evaluate(arm, fold, partition, self.prep.plan[name], seed, candidates[family])
                self._save(self.folds, seed, label, rows, info)

    def _save(self, store: FoldStore, seed: int, label: str, rows: list[dict], info: dict) -> None:
        store.save(self.prep.ds.name, seed, label, rows)
        path = self.accounting_dir / f"{store.directory.name}__seed{seed}__{label.replace(':', '__')}.json"
        path.write_text(json.dumps({"seed": seed, "label": label, **info}, indent=1, default=float), encoding="utf-8")
        gc.collect()

    # ----- nested selection -----
    def selection(self, arm: str, seed: int) -> None:
        ds, config = self.prep.ds, self.config
        partition = make_partition(ds.family, seed, config.val_fraction, config.test_fraction)
        labels = ds.family.astype(str)
        for pair in itertools.combinations(self.prep.families, 2):
            label = f"{arm}:pair:{pair[0]}+{pair[1]}"
            if self.inner.done(ds.name, seed, label):
                continue
            uncapped = partition.train[~np.isin(labels[partition.train], pair)]
            reference = self.prep.plan[protocol.REFERENCE]

            def fit(ds_, kept, threshold_benign, config_, seed_, pair=pair, uncapped=uncapped):
                models, by_copies, infos = {}, {}, {}
                for candidate in protocol.CANDIDATES:
                    ratio = float(candidate)
                    replay = replay_for(arm, kept, ds.family, self.events[seed_], ratio, seed_)
                    key = replay.copies.tobytes()
                    infos[candidate] = accounting(kept, ds.family, replay)
                    if key in by_copies:  # Identical training data, so the identical fit is reused.
                        models[candidate] = by_copies[key]
                        continue
                    models[candidate] = by_copies[key] = self._fit(
                        arm=arm, train=kept, config_a_train=kept, replay=replay,
                        expected_total=allocate_b(kept, ds.family, self.events[seed_], ratio, seed_).total,
                        excluded={"validation": partition.val, "test": partition.test,
                                  "cap-excluded": np.setdiff1d(uncapped, kept)},
                        test=None, held_out=set(pair), seed=seed_, treatment=reference, val_benign=threshold_benign,
                        context=f"seed{seed_}:pair:{pair[0]}+{pair[1]}",
                    )
                self._pending_info = infos
                return ((lambda rows: {c: m.scores(ds.X.iloc[rows]) for c, m in models.items()}),
                        {c: m.val_benign_scores for c, m in models.items()})

            with self.ledger.fit(self.stage, f"{label}:seed{seed}"):  # Every fit and score of the inner fold.
                rows = pair_rows(pair, partition.train, partition.val, ds, config, seed, fit, protocol.CANDIDATES)
            for row in rows:
                row["arm"] = arm
                row["fold_group"] = protocol.fold_group(row["outer_family"], row["inner_family"])
                info = self._pending_info[row["candidate"]]
                row["replay_total"] = info["replay_total"]
                row["attack_ess"] = info["attack_class"]["ess"]
            self._save(self.inner, seed, label, rows, {"candidates": self._pending_info})

    def selected(self, arm: str) -> pd.DataFrame:
        rows = self.inner.load_all()
        rows = rows[rows["arm"] == arm].copy()
        rows["candidate"] = rows["candidate"].astype(str).map(lambda c: f"{float(c):g}")
        return select(rows, self.config.target_fprs[0], protocol.CANDIDATES)

    def candidates_for(self, arm: str, seed: int) -> dict[str | None, str]:
        """The ratio of each outer fold: the arm's selection per held-out family; the default for the seen fold."""
        if arm == "A":
            return {None: "0", **{f: "0" for f in self.prep.families}}
        chosen = self.selected(arm)
        chosen = chosen[chosen["seed"] == seed].set_index("outer_family")["selected"]
        missing = [f for f in self.prep.families if f not in chosen.index or chosen[f] == "none"]
        if missing:
            raise StopRun(f"{arm} has no selected ratio for seed {seed}, families {missing}: run its selection stage first")
        return {None: SEEN_FOLD_CANDIDATE, **{f: f"{float(chosen[f]):g}" for f in self.prep.families}}

    # ----- stages -----
    def run_stage(self, stage: str) -> dict:
        if stage not in protocol.STAGES:
            raise ValueError(f"unknown stage {stage!r}; stage 6 is excluded (section 11)")
        finished = [s for s in protocol.STAGES if s != stage and (self.out / f"stage_{s}.done").exists()]
        order = protocol.STAGES.index(stage)
        if any(s not in finished for s in protocol.STAGES[:order]):
            raise StopRun(f"stage {stage} needs every earlier stage finished first: {protocol.STAGES[:order]}")
        projection = self.ledger.before_stage(stage, finished)
        self.stage, self.gate_pending = stage, True
        seeds = list(self.config.seeds)
        self.log(f"stage {stage}: {STAGE_WORK[stage]}; projection {projection['projected_total']:.1f} CPU-h")
        if stage == "1":
            self.outer("A", seeds[0], self.candidates_for("A", seeds[0]), self.folds)
        elif stage in ("2a", "2b"):
            arm = "B" if stage == "2a" else "B0"
            for seed in seeds:
                self.selection(arm, seed)
            self.selected(arm).to_csv(self.out / f"selections_{arm}.csv", index=False)
            if stage == "2b":
                control = analysis.neither_family_control(self.inner.load_all())
                (self.out / "neither_family_control.json").write_text(json.dumps(control, indent=1), encoding="utf-8")
        elif stage == "3":
            for seed in seeds[1:]:
                self.outer("A", seed, self.candidates_for("A", seed), self.folds)
            for arm in ("B", "B0"):
                for seed in seeds:
                    self.outer(arm, seed, self.candidates_for(arm, seed), self.folds)
        elif stage in ("4a", "4b", "4c"):
            arm = {"4a": "B", "4b": "B0", "4c": "A"}[stage]
            for seed in seeds:
                self.audit(arm, seed, self.candidates_for(arm, seed))
        elif stage == "5":
            for arm in protocol.ARMS:
                for seed in seeds:
                    self.outer(arm, seed, self.candidates_for(arm, seed), self.rerun)
            original = self.folds.load_all()
            original = original[original["treatment"] == protocol.REFERENCE]
            report = analysis.compare_exact(original, self.rerun.load_all())
            (self.out / "determinism.json").write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
            if not report["passed"]:
                raise StopRun(f"determinism check failed: {report['n_differences']} differing values "
                              f"(determinism.json). Results are labelled not reproduced; the owner decides.")
        self.ledger.end_stage(stage)
        (self.out / f"stage_{stage}.done").write_text(json.dumps(projection, indent=1), encoding="utf-8")
        return projection

    def report(self) -> dict:
        """Write the result tables once every stage has finished. Fits nothing."""
        missing = [s for s in protocol.STAGES if not (self.out / f"stage_{s}.done").exists()]
        if missing:
            raise StopRun(f"stages {missing} have not finished; results are not final before stage 5 (section 10)")
        results = self.folds.load_all()
        samples, primary = self.config.bootstrap_samples, self.config.target_fprs[0]
        results.to_csv(self.out / "results.csv", index=False)
        tables = analysis.report_tables(results, self.inner.load_all(), samples, primary)
        for name, table in tables.items():
            if isinstance(table, pd.DataFrame):
                table.to_csv(self.out / f"{name}.csv", index=False)
        summary = {k: v for k, v in tables.items() if not isinstance(v, pd.DataFrame)}
        summary["limitations"] = analysis.LIMITATIONS
        (self.out / "summary.json").write_text(json.dumps(summary, indent=1, default=str), encoding="utf-8")
        return summary


def guard(stage: str, config: BaselineConfig) -> dict:
    """Default-deny checks before any stage (module docstring). Returns the compute approvals in force."""
    from aegis.config_b.identity import authorization
    from aegis.frozen import verify_config_a

    verify_config_a(config)
    return authorization(stage)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/baseline.yaml")
    parser.add_argument("--out", default="results/config_b")
    parser.add_argument("--bank", default=str(protocol.DEFAULT_BANK_DIR))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--stage", choices=protocol.STAGES)
    group.add_argument("--report", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    from aegis.config_b.bank import verify_bank

    approvals = guard(args.stage or "report", config)
    events = verify_bank(Path(args.bank))["events"]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(out / "compute_ledger.csv", approvals["approved_budget"], approvals["past_planning_ceiling"])
    with ledger.fit(args.stage or "report", "load and clean the dataset"):  # Loading CPU is measured too.
        prepared = prepare(config)
    runner = Runner(prepared, config, out, events, ledger)
    try:
        print(json.dumps(runner.report() if args.report else runner.run_stage(args.stage), indent=1, default=str))
    except (StopRun, InvariantViolation) as stop:
        print(f"STOPPED: {stop}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
