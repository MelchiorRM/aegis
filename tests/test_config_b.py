"""Config B: the mandatory tests T1-T10 (pre-registration section 7) and the runner's safeguards.

Synthetic data only. Config A's code is imported and never patched, except where a test records a call
(monkeypatch is undone after each test).
"""

import dataclasses
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from aegis.config import BaselineConfig, DatasetConfig, RandomForestConfig
from aegis.config_b import analysis, bank, identity, model as cb_model, protocol
from aegis.config_b.compute import Ledger, StopRun
from aegis.config_b.experiment import Runner, prepare
from aegis.config_b.model import (
    FingerprintRegistry, InvariantViolation, ReplayForest, check_replay_rows, check_settings,
    preprocessing_fingerprint, preprocessing_gate,
)
from aegis.config_b.replay import (
    accounting, allocate_b, allocate_b0, cyclic_draws, kish, kish_cyclic, multiplicities, replay_for,
)
from aegis.data.dataset import BENIGN, Dataset, remove_duplicates
from aegis.data.loaders import generate_synthetic
from aegis.data.splits import cap_per_family, holdout_fold, make_partition
from aegis.experiments import artifacts
from aegis.frozen import FROZEN
from aegis.models.baseline import RandomForestBaseline, build_preprocessor

ROOT = Path(__file__).resolve().parents[1]
RENAME = {"scan": "portscan", "flood": "dos", "exfil": "brute_force", "beacon": "bot"}
EVENTS = {s: {"brute_force": 2398, "portscan": 4046} for s in range(5)}
FROZEN_RF = RandomForestConfig(**FROZEN["settings"]["rf"], n_jobs=2)


def synthetic_raw(n_benign: int = 3000) -> Dataset:
    ds = generate_synthetic("synthetic_cb", seed=3, n_benign=n_benign)
    return Dataset(ds.name, ds.X, np.array([RENAME.get(f, f) for f in ds.family], dtype=object))


def small_config(**changes) -> BaselineConfig:
    base = BaselineConfig(datasets=(DatasetConfig(kind="synthetic", name="synthetic_cb"),), seeds=(0, 1),
                          max_train_per_family=300, min_family_count=100, bootstrap_samples=500, rf=FROZEN_RF)
    return dataclasses.replace(base, **changes)


def mixed_frame(n: int = 200, seed: int = 0) -> tuple[pd.DataFrame, np.ndarray]:
    """Numeric columns with missing values, and a category at the min_frequency boundary (20) and below it."""
    rng = np.random.default_rng(seed)
    proto = np.array(["tcp"] * (n - 39) + ["edge20"] * 20 + ["rare19"] * 19, dtype=object)
    rng.shuffle(proto)
    a = rng.lognormal(0, 1, n)
    a[rng.choice(n, 15, replace=False)] = np.nan
    frame = pd.DataFrame({"a": a, "b": rng.normal(0, 3, n), "proto": proto})
    y = (rng.random(n) < 0.3).astype(np.int8)
    y[:2] = [0, 1]
    return frame, y


# ---------- T1-T4: the fit wrapper ----------

def test_t1_preprocessing_reproduces_config_a_bit_for_bit():
    frame, y = mixed_frame()
    wrapper = ReplayForest(FROZEN_RF, 0).preprocess(frame, ["a", "b"], ["proto"])
    config_a = RandomForestBaseline(FROZEN_RF, 0).fit(frame, y, frame.iloc[:5], ["a", "b"], ["proto"])
    expected = config_a.preprocessor.transform(frame).astype(np.float32)
    assert wrapper.distinct.dtype == expected.dtype and wrapper.distinct.tobytes() == expected.tobytes()
    encoder = wrapper.preprocessor.named_transformers_["categorical"]
    assert "edge20" in list(encoder.categories_[0]) and "rare19" in list(encoder.infrequent_categories_[0])
    preprocessing_gate(wrapper, frame, y, frame.iloc[:5], ["a", "b"], ["proto"])  # Invariant 6 passes.


@pytest.mark.parametrize("n_jobs", [1, 3])
def test_t2_zero_replay_scores_equal_config_a(n_jobs):
    frame, y = mixed_frame(300, seed=1)
    rf = dataclasses.replace(FROZEN_RF, n_jobs=n_jobs)
    wrapper = ReplayForest(rf, 4).fit(frame, y, np.empty(0, dtype=np.int64), frame.iloc[:40], ["a", "b"], ["proto"])
    config_a = RandomForestBaseline(dataclasses.replace(FROZEN_RF, n_jobs=1), 4).fit(
        frame, y, frame.iloc[:40], ["a", "b"], ["proto"])
    probe = frame.iloc[::3]
    assert wrapper.scores(probe).tobytes() == config_a.scores(probe).tobytes()
    assert wrapper.val_benign_scores.tobytes() == config_a.val_benign_scores.tobytes()


def test_t3_copies_not_weights(monkeypatch):
    frame, y = mixed_frame(150, seed=2)
    positions = np.array([3, 3, 7, 10, 149])
    seen = {}
    original = RandomForestClassifier.fit

    def recording_fit(self, X, y_, sample_weight=None):
        seen.update(X=np.array(X), y=np.array(y_), sample_weight=sample_weight, params=self.get_params())
        return original(self, X, y_)

    monkeypatch.setattr(RandomForestClassifier, "fit", recording_fit)
    wrapper = ReplayForest(FROZEN_RF, 0).fit(frame, y, positions, frame.iloc[:5], ["a", "b"], ["proto"])
    assert np.array_equal(seen["X"], np.concatenate([wrapper.distinct, wrapper.distinct[positions]]))
    assert np.array_equal(seen["y"], np.concatenate([y, y[positions]]))
    assert seen["sample_weight"] is None
    params = seen["params"]
    assert params["class_weight"] == "balanced_subsample"
    assert (params["n_estimators"], params["max_depth"], params["min_samples_leaf"]) == (100, 20, 2)
    assert wrapper.n_fit_rows == len(frame) + len(positions)


def test_t4_copies_never_refit_preprocessing():
    frame, y = mixed_frame(200, seed=3)
    rare = np.flatnonzero(frame["proto"].to_numpy() == "rare19")
    copies = np.repeat(rare[:5], 3)  # 19 + 15 = 34 rows of "rare19" in the fitted matrix.
    zero = ReplayForest(FROZEN_RF, 0).fit(frame, y, np.empty(0, dtype=np.int64), frame.iloc[:5], ["a", "b"], ["proto"])
    many = ReplayForest(FROZEN_RF, 0).fit(frame, y, copies, frame.iloc[:5], ["a", "b"], ["proto"])
    assert preprocessing_fingerprint(zero.preprocessor, zero.distinct) == preprocessing_fingerprint(many.preprocessor, many.distinct)
    assert zero.distinct.shape[1] == many.distinct.shape[1] == many.forest.n_features_in_


# ---------- T5-T6, T10: replay ----------

@pytest.fixture(scope="module")
def prepared():
    return prepare(small_config(), synthetic_raw(), required_treatments=("reference", "remove_matching_signatures"))


def test_t5_pool_boundaries_outer_inner_and_treatments(prepared):
    ds, config = prepared.ds, small_config()
    labels = ds.family.astype(str)
    for seed in (0, 1):
        part = make_partition(ds.family, seed, config.val_fraction, config.test_fraction)
        contexts = []
        for family in prepared.families:
            fold = holdout_fold(part, ds.family, family, config.max_train_per_family, seed)
            uncapped = part.train[labels[part.train] != family]
            for treatment in prepared.plan.values():
                train = artifacts.training_rows(fold, ds, treatment, prepared.flow_signatures)
                contexts.append((train, np.setdiff1d(uncapped, fold.train), {family}))
        for a, b in [("bot", "dos"), ("brute_force", "portscan"), ("dos", "portscan")]:
            uncapped = part.train[~np.isin(labels[part.train], [a, b])]
            kept = cap_per_family(uncapped, ds.family, config.max_train_per_family, seed)
            contexts.append((kept, np.setdiff1d(uncapped, kept), {a, b}))
        for train, cap_excluded, held in contexts:
            assert len(cap_excluded)  # The cap binds in this configuration, so the boundary is exercised.
            for arm in ("B", "B0"):
                for ratio in protocol.RATIOS:
                    copies = replay_for(arm, train, ds.family, EVENTS[seed], ratio, seed).copies
                    assert np.isin(copies, train).all()
                    for forbidden in (part.val, part.test, cap_excluded):
                        assert not np.isin(copies, forbidden).any()
                    assert not np.isin(labels[copies], list(held)).any()


def test_t6_allocation_cap_and_matching(prepared):
    ds = prepared.ds
    labels = ds.family.astype(str)
    part = make_partition(ds.family, 0)
    fold = holdout_fold(part, ds.family, "bot", 300, 0)
    train = fold.train
    n = {f: int((labels[train] == f).sum()) for f in protocol.MAPPED_FAMILIES}
    p = {f: EVENTS[0][f] / sum(EVENTS[0].values()) for f in n}
    b = allocate_b(train, ds.family, EVENTS[0], 0.5, 0)
    total = int(round(0.5 * sum(n.values())))
    assert b.requested == {f: int(round(total * p[f])) for f in n} and b.realized == b.requested
    drawn = labels[b.copies]
    assert {f: int((drawn == f).sum()) for f in n} == b.realized
    for f in n:  # Cyclic without replacement: replay counts within a family differ by at most one.
        counts = multiplicities(train[labels[train] == f], b.copies[drawn == f]) - 1
        assert counts.max() - counts.min() <= 1
    # The cap truncates without redistributing: skew the events so one family exceeds 4 replays per row.
    skewed = allocate_b(train, ds.family, {"brute_force": 1, "portscan": 99}, 10.0, 0)
    assert skewed.truncated["portscan"] > 0 and skewed.realized["portscan"] == 4 * n["portscan"]
    assert skewed.truncated["brute_force"] == 0 and skewed.realized["brute_force"] == skewed.requested["brute_force"]
    # B0: B's realized total, drawn from every seen attack family, mapped or not.
    b0 = replay_for("B0", train, ds.family, EVENTS[0], 0.5, 0)
    assert b0.total == b.total and set(b0.realized) - set(protocol.MAPPED_FAMILIES)  # dos rows are drawn too.
    assert not np.isin(labels[b0.copies], [BENIGN, "bot"]).any()
    # Seeded and reproducible.
    again = allocate_b(train, ds.family, EVENTS[0], 0.5, 0)
    assert np.array_equal(again.copies, b.copies)
    assert not np.array_equal(allocate_b(train, ds.family, EVENTS[0], 0.5, 1).copies, b.copies)
    assert np.array_equal(allocate_b0(train, ds.family, 50, 0.5, 0).copies, allocate_b0(train, ds.family, 50, 0.5, 0).copies)
    # One mapped family held out: all of B's replay goes to the other one.
    single = holdout_fold(part, ds.family, "brute_force", 300, 0)
    only = allocate_b(single.train, ds.family, EVENTS[0], 1.0, 0)
    assert set(only.realized) == {"portscan"} and only.excluded_held_out == {"brute_force": 2398}
    # No mapped family in training: B and B0 add nothing.
    none = np.sort(single.train[labels[single.train] != "portscan"])
    assert replay_for("B", none, ds.family, EVENTS[0], 1.0, 0).total == 0
    assert replay_for("B0", none, ds.family, EVENTS[0], 1.0, 0).total == 0


@pytest.mark.parametrize("n,m", [(1, 0), (7, 3), (7, 7), (7, 30), (100, 250), (4159, 3266)])
def test_t10_kish_matches_closed_form_and_never_exceeds_n(n, m):
    rows = np.arange(n)
    weights = multiplicities(rows, cyclic_draws(rows, m, np.random.default_rng(0)))
    assert kish(weights) == pytest.approx(kish_cyclic(n, m), rel=1e-12)
    assert kish(weights) <= n + 1e-9


def test_accounting_reports_ess_beside_nominal_counts(prepared):
    ds = prepared.ds
    fold = holdout_fold(make_partition(ds.family, 0), ds.family, "dos", 300, 0)
    b = replay_for("B", fold.train, ds.family, EVENTS[0], 1.0, 0)
    info = accounting(fold.train, ds.family, b)
    assert info["attack_class"]["replays"] == b.total
    assert info["attack_class"]["ess"] <= info["attack_class"]["distinct"]
    assert info["families"]["portscan"]["nominal"] == info["families"]["portscan"]["distinct"] + b.realized["portscan"]


# ---------- T7: invariant failures stop ----------

def base_rows():
    train = np.array([1, 2, 3, 5, 8, 13])
    return dict(arm="B", train=train, config_a_train=train.copy(), copies=np.array([2, 5]), expected_total=2,
                excluded={"validation": np.array([20, 21]), "test": np.array([30]), "cap-excluded": np.array([4])})


@pytest.mark.parametrize("change,message", [
    ({"config_a_train": np.array([1, 2, 3, 5, 8])}, "invariant 1"),
    ({"copies": np.array([2, 6])}, "invariant 1"),
    ({"copies": np.array([2, 4]), "train": np.array([1, 2, 3, 4, 5]), "config_a_train": np.array([1, 2, 3, 4, 5])}, "cap-excluded"),
    ({"copies": np.array([2, 30]), "train": np.array([2, 30]), "config_a_train": np.array([2, 30])}, "test row"),
    ({"expected_total": 3}, "invariant 4"),
    ({"arm": "A"}, "invariant 4"),
])
def test_t7_row_invariants_raise(change, message):
    with pytest.raises(InvariantViolation, match=message):
        check_replay_rows(**{**base_rows(), **change})


def test_t7_held_out_family_and_test_vector_raise():
    family = np.array(["benign", "bot", "dos", "dos", "bot", "dos"], dtype=object)
    args = {**base_rows(), "train": np.array([1, 2, 3, 5]), "config_a_train": np.array([1, 2, 3, 5]),
            "copies": np.array([1]), "expected_total": 1, "excluded": {}}
    with pytest.raises(InvariantViolation, match="held-out family"):
        check_replay_rows(**args, family=family, held_out="bot")
    flows = np.array([10, 11, 12, 13, 14, 11])
    with pytest.raises(InvariantViolation, match="feature vector"):
        check_replay_rows(**args, flows=flows, test=np.array([5]))


def test_t7_settings_registry_and_gate_raise(tmp_path):
    with pytest.raises(InvariantViolation, match="invariant 5"):
        check_settings(dataclasses.replace(FROZEN_RF, min_samples_leaf=1), 0, 0)
    with pytest.raises(InvariantViolation, match="invariant 5"):
        check_settings(FROZEN_RF, 1, 0)
    registry = FingerprintRegistry(tmp_path / "fp.json")
    registry.check("ctx", "aaa")
    with pytest.raises(InvariantViolation, match="invariant 3"):
        FingerprintRegistry(tmp_path / "fp.json").check("ctx", "bbb")  # Persisted across arms and stages.
    frame, y = mixed_frame()
    wrapper = ReplayForest(FROZEN_RF, 0).preprocess(frame, ["a", "b"], ["proto"])
    wrapper.distinct = wrapper.distinct.copy()
    wrapper.distinct[0, 0] += 1e-3
    with pytest.raises(InvariantViolation, match="invariant 6"):
        preprocessing_gate(wrapper, frame, y, frame.iloc[:5], ["a", "b"], ["proto"])


def test_t7_a_failed_invariant_leaves_no_fold_output(prepared, tmp_path, monkeypatch):
    from aegis.config_b import experiment
    from aegis.config_b.replay import Replay

    def leaking(arm, train, family, events, ratio, fold_seed):
        return Replay(arm, ratio, np.array([int(np.setdiff1d(np.arange(len(family)), train)[0])]))

    runner = Runner(prepared, small_config(), tmp_path, EVENTS, Ledger(tmp_path / "ledger.csv"), log=lambda _: None)
    monkeypatch.setattr(experiment, "replay_for", leaking)
    runner.stage = "3"
    with pytest.raises(InvariantViolation):
        runner.outer("B", 0, {None: "0.25", **{f: "0.25" for f in prepared.families}}, runner.folds)
    assert not list((tmp_path / "folds").glob("*.csv"))
    assert not list((tmp_path / "accounting").glob("*.json"))


# ---------- T8-T9: outcome counting and seeds ----------

def step(outcome, *actions):
    return {"red": {"red_agent_0": {"success": outcome, "actions": list(actions)}}}


def test_t8_outcome_counting():
    ssh = {"type": "ExploitRemoteService", "sub_action": "SSHBruteForce"}
    log = [
        step("IN_PROGRESS", {"type": "Sleep"}),                  # O1: an in-progress tick, logged as Sleep.
        step("TRUE", ssh),                                        # O2.
        step("FALSE", ssh),                                       # O3: failed but reached the service.
        step("FALSE", {"type": "ExploitRemoteService"}),          # O4: no service chosen.
        step("UNKNOWN", {"type": "AggressiveServiceDiscovery"}),  # O6.
        step("IN_PROGRESS", {"type": "StealthServiceDiscovery"}),  # Non-Sleep in progress: never counted.
        step("TRUE", {"type": "AggressiveServiceDiscovery"}),
        step("TRUE", {"type": "Impact"}),
        step("UNKNOWN", {"type": "Sleep"}),
    ]
    counts = bank.count_actions(json.dumps(s) for s in log)
    assert counts[("mapped", "brute_force")] == 2 and counts[("mapped", "portscan")] == 1
    assert counts[("attempt", "ExploitRemoteService", "SSHBruteForce")] == 2
    assert counts[("success", "ExploitRemoteService", "SSHBruteForce")] == 1
    assert counts[("O4",)] == 1
    assert counts[("O6", "AggressiveServiceDiscovery", "")] == 1
    assert counts[("O1", "StealthServiceDiscovery", "")] == 1
    assert counts[("attempt", "Impact", "")] == 1
    assert sum(n for k, n in counts.items() if k[0] == "attempt") == 4


def test_t9_seed_derivation():
    seeds = [s for _, _, s in protocol.bank_seeds()]
    assert len(seeds) == len(set(seeds)) == 250 and min(seeds) == 0 and max(seeds) == 4049
    for bad in (1000, -1):
        with pytest.raises(ValueError):
            protocol.sim_seed(0, bad)
    manifest = json.loads(protocol.BANK_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["seeds"]["rule"] == "sim_seed = 1000 * fold_seed + episode"
    assert sorted(e["sim_seed"] for e in manifest["episodes"]) == sorted(seeds)


def test_bank_check_refuses_an_altered_manifest(tmp_path):
    altered = tmp_path / "manifest.json"
    altered.write_text(protocol.BANK_MANIFEST.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(bank.BankMismatch, match="not the registered manifest"):
        bank.verify_bank(tmp_path, altered)


@pytest.mark.skipif(not protocol.DEFAULT_BANK_DIR.exists(), reason="the scenario bank is not on this machine")
def test_real_bank_passes_and_matches_the_registered_weights():
    result = bank.verify_bank()
    registered = json.loads(protocol.AMENDMENT.read_text(encoding="utf-8"))["mapping"]["weights"]
    for seed, events in result["events"].items():
        total = sum(events.values())
        assert {f: round(n / total, 6) for f, n in events.items()} == registered[str(seed)]
        assert result["report"][seed]["O1_in_progress_non_sleep"] == 0


# ---------- fold groups, classification, compute ----------

def test_fold_groups_match_the_registered_table():
    inner = [(o, i) for o in protocol.HELD_OUT_FAMILIES for i in protocol.HELD_OUT_FAMILIES if o != i]
    groups = [protocol.fold_group(o, i) for o, i in inner]
    assert (groups.count("two_family"), groups.count("single_family"), groups.count("neither_family")) == (2, 8, 2)
    assert {(o, i) for (o, i), g in zip(inner, groups) if g == "neither_family"} == {
        ("brute_force", "portscan"), ("portscan", "brute_force")}
    assert [protocol.fold_group(f) for f in protocol.HELD_OUT_FAMILIES] == [
        "two_family", "single_family", "two_family", "single_family"]


@pytest.mark.parametrize("low,high,expected", [
    (0.01, 0.2, "positive"), (-0.3, -0.001, "negative"), (-0.1, 0.1, "inconclusive"), (0.0, 0.2, "inconclusive"),
    (float("nan"), 0.1, "not estimable"),
])
def test_classification_uses_the_interval_alone(low, high, expected):
    assert analysis.classify(low, high) == expected


def ledger_with(tmp_path, hours_by_stage, **kwargs):
    ledger = Ledger(tmp_path / "ledger.csv", **kwargs)
    for stage, hours in hours_by_stage.items():
        ledger.rows.append({"stage": stage, "label": "x", "cpu_seconds": hours * 3600, "wall_seconds": 1.0})
    return ledger


def test_compute_stops_above_the_approved_budget_with_the_required_report(tmp_path):
    ledger = ledger_with(tmp_path, {"1": 0.506667 * 1.2})  # 20% over the ceiling.
    with pytest.raises(StopRun) as stop:
        ledger.before_stage("2a", ["1"])
    text = str(stop.value)
    for item in ("approved planning budget 71.5", "measured_by_stage", "remaining_estimates", "reason", "proposed changes"):
        assert item in text
    ok = ledger_with(tmp_path, {"1": 0.506667})
    assert ok.before_stage("2a", ["1"])["projected_total"] == pytest.approx(
        protocol.STAGE0_SPENT_CPU_HOURS + sum(protocol.STAGE_CEILINGS.values()), rel=1e-6)


def test_153_and_180_are_hard_limits_not_permission(tmp_path):
    ceilings = sum(protocol.STAGE_CEILINGS.values())
    ratio = (160 - protocol.STAGE0_SPENT_CPU_HOURS) / ceilings  # Projects to 160: above 153, below 180.
    ledger = ledger_with(tmp_path, {"1": 0.506667 * ratio}, approved_budget=170.0)
    with pytest.raises(StopRun, match="153"):
        ledger.before_stage("2a", ["1"])
    allowed = ledger_with(tmp_path, {"1": 0.506667 * ratio}, approved_budget=170.0, past_planning_ceiling=True)
    assert allowed.before_stage("2a", ["1"])
    over = ledger_with(tmp_path, {"1": 0.506667 * (190 - protocol.STAGE0_SPENT_CPU_HOURS) / ceilings},
                       approved_budget=999.0, past_planning_ceiling=True)
    with pytest.raises(StopRun, match="hard stop"):
        over.before_stage("2a", ["1"])


def test_in_stage_stop_at_175_happens_at_a_fit_boundary(tmp_path):
    ledger = ledger_with(tmp_path, {"3": 175.0 - protocol.STAGE0_SPENT_CPU_HOURS - 1e-6})
    with pytest.raises(StopRun, match="fit boundary"):
        with ledger.fit("3", "last fit"):
            sum(range(200_000))
    assert ledger.rows[-1]["label"] == "last fit"  # The finished fit is recorded before the stop.
    with pytest.raises(StopRun, match="reached"):
        with ledger.fit("3", "never runs"):
            raise AssertionError("must not run")


# ---------- the runner end to end on synthetic data ----------

@pytest.fixture(scope="module")
def finished_run(prepared, tmp_path_factory):
    out = tmp_path_factory.mktemp("config_b")
    runner = Runner(prepared, small_config(), out, EVENTS, Ledger(out / "compute_ledger.csv"), log=lambda _: None)
    for stage in protocol.STAGES:
        runner.run_stage(stage)
    return runner, runner.report(), out


def test_runner_stages_in_order_and_refuses_skipping(prepared, tmp_path):
    runner = Runner(prepared, small_config(), tmp_path, EVENTS, Ledger(tmp_path / "l.csv"), log=lambda _: None)
    with pytest.raises(StopRun, match="earlier stage"):
        runner.run_stage("2a")
    with pytest.raises(ValueError, match="excluded"):
        runner.run_stage("6")
    with pytest.raises(StopRun, match="not finished"):
        runner.report()


def test_runner_end_to_end(finished_run):
    runner, summary, out = finished_run
    results = pd.read_csv(out / "results.csv")
    held = results[(results["fold"] == "holdout") & (results["treatment"] == "reference")]
    assert set(held["arm"]) == {"A", "B", "B0"} and set(held["family"]) == set(protocol.HELD_OUT_FAMILIES)
    assert (held[held["arm"] == "A"]["replay_total"] == 0).all()
    assert (held[held["arm"] == "B"]["replay_total"] > 0).all()
    # B0 adds exactly B's realized total at B0's own ratio; where the arms chose the same ratio, the totals match.
    b = held[held["arm"] == "B"].set_index(["seed", "family", "target_fpr"])
    b0 = held[held["arm"] == "B0"].set_index(["seed", "family", "target_fpr"])
    same = b["ratio"] == b0["ratio"]
    assert (b.loc[same, "replay_total"] == b0.loc[same, "replay_total"]).all()
    contrasts = pd.read_csv(out / "contrasts.csv")
    primary = contrasts[contrasts["role"] == "primary"]
    assert set(primary["contrast"]) == {"B - B0"} and len(primary) == 4
    assert set(primary["classification"]) <= {"positive", "negative", "inconclusive", "not estimable"}
    assert dict(zip(primary["family"], primary["fold_group"])) == {
        "bot": "two_family", "dos": "two_family", "brute_force": "single_family", "portscan": "single_family"}
    assert set(summary["primary_by_fold_group"]) == {"two_family", "single_family"}
    assert summary["neither_family_control"]["identical"] is True
    assert json.loads((out / "determinism.json").read_text())["passed"] is True
    assert {"A", "B", "B0"} <= set(pd.read_csv(out / "shortcut_effects.csv")["arm"])
    seen = results[results["fold"] == "seen"]
    assert (seen[seen["arm"] != "A"]["ratio"] == 0.25).all()  # Proposed amendment 1 (G1).
    ledger = pd.read_csv(out / "compute_ledger.csv")
    assert set(ledger["stage"]) == set(protocol.STAGES)
    assert set(ledger[ledger["stage"] == "1"]["label"].str.split(":").str[0]) == {"A"}  # Proposed amendment 1 (G2).


def test_arm_a_rows_equal_the_artifact_audit_rows(prepared, finished_run):
    """The Config B evaluation reproduces Config A's audit evaluation exactly for arm A (extends T2)."""
    runner, _, out = finished_run
    results = pd.read_csv(out / "results.csv")
    config = small_config()
    ds = prepared.ds
    for seed, family in [(0, "bot"), (1, "portscan")]:
        part = make_partition(ds.family, seed, config.val_fraction, config.test_fraction)
        fold = holdout_fold(part, ds.family, family, config.max_train_per_family, seed)
        expected = pd.DataFrame(artifacts._fold_rows(
            ds, prepared.plan["reference"], fold, seed, config, prepared.flow_signatures, prepared.indicators,
            prepared.raw_rows, prepared.flows))
        got = results[(results["arm"] == "A") & (results["seed"] == seed) & (results["family"] == family)
                      & (results["fold"] == "holdout") & (results["treatment"] == "reference")]
        got = got.sort_values("target_fpr").reset_index(drop=True)
        expected = expected.sort_values("target_fpr").reset_index(drop=True)
        shared = [c for c in expected.columns if c in got.columns and c not in ("fit_seconds",)]
        assert len(shared) > 25
        pd.testing.assert_frame_equal(got[shared], expected[shared], check_exact=True, check_dtype=False)


def test_determinism_comparison_reports_any_difference():
    frame = pd.DataFrame({"dataset": ["d"] * 2, "arm": ["A", "B"], "seed": [0, 0], "fold": ["holdout"] * 2,
                          "treatment": ["reference"] * 2, "family": ["bot"] * 2, "target_fpr": [0.01] * 2,
                          "raw_recall": [0.5, np.nan], "fit_seconds": [1.0, 2.0]})
    assert analysis.compare_exact(frame, frame.assign(fit_seconds=[9.0, 9.0]))["passed"]
    changed = frame.copy()
    changed.loc[0, "raw_recall"] = 0.5 + 1e-15
    report = analysis.compare_exact(frame, changed)
    assert not report["passed"] and report["differences"][0]["column"] == "raw_recall"


def test_neither_family_control_stops_on_a_difference():
    rows = pd.DataFrame({"seed": [0, 0], "outer_family": ["brute_force"] * 2, "inner_family": ["portscan"] * 2,
                         "target_fpr": [0.01] * 2, "fold_group": ["neither_family"] * 2, "arm": ["B", "B0"],
                         "candidate": ["0.25"] * 2, "inner_recall": [0.4, 0.41], "inner_fpr": [0.01, 0.01],
                         "replay_total": [0, 0]})
    with pytest.raises(InvariantViolation, match="neither-family"):
        analysis.neither_family_control(rows)


# ---------- authorization and agreement with the registered amendment ----------

def amendment(tmp_path, **changes):
    record = json.loads(protocol.AMENDMENT.read_text(encoding="utf-8"))
    record.update({"amendments": [], **changes})  # Each test sets the amendments it needs.
    path = tmp_path / "config_b.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def signed_addendum(identity_value=None, when="2026-11-11T00:00:00Z"):
    return {"config_b_identity": identity_value or identity.digest(), "signed_by": "MelchiorRM", "signed_utc": when}


def test_no_stage_runs_without_a_signed_identity_addendum_and_stage_authorization(tmp_path):
    with pytest.raises(PermissionError, match="identity addendum"):
        identity.authorization("1", amendment(tmp_path))
    with pytest.raises(PermissionError, match="not the signed"):
        identity.authorization("1", amendment(tmp_path, identity_addendum=signed_addendum("0" * 16)))
    with pytest.raises(PermissionError, match="stage 1 is not authorized"):
        identity.authorization("1", amendment(tmp_path, identity_addendum=signed_addendum()))
    early = [{"stages": ["1"], "authorized_by": "MelchiorRM", "authorized_utc": "2026-11-10T23:00:00Z"}]
    with pytest.raises(PermissionError, match="after the identity addendum"):
        identity.authorization("1", amendment(tmp_path, identity_addendum=signed_addendum(), stage_authorizations=early))
    granted = [{"stages": ["1", "2a"], "authorized_by": "MelchiorRM", "authorized_utc": "2026-11-11T01:00:00Z"}]
    path = amendment(tmp_path, identity_addendum=signed_addendum(), stage_authorizations=granted)
    assert identity.authorization("2a", path) == {"approved_budget": 71.5, "past_planning_ceiling": False}
    with pytest.raises(PermissionError):
        identity.authorization("2b", path)
    with pytest.raises(PermissionError):
        identity.authorization("report", path)
    unsigned = amendment(tmp_path, identity_addendum=signed_addendum(), stage_authorizations=granted,
                         amendments=[{"number": 1, "amended_by": None}])
    with pytest.raises(PermissionError, match="amendment 1 is not signed"):
        identity.authorization("1", unsigned)


def test_the_registered_amendment_has_no_stage_authorized():
    with pytest.raises(PermissionError, match="amendment 1 is not signed"):  # Draft amendment 1 keeps every stage closed.
        identity.authorization("1")
    record = json.loads(protocol.AMENDMENT.read_text(encoding="utf-8"))
    assert record["identity_addendum"]["config_b_identity"] == identity.digest()  # The draft names the current code.
    assert record["identity_addendum"]["signed_by"] is None and record["stage_authorizations"] == []


def test_protocol_constants_agree_with_the_registered_amendment():
    record = json.loads(protocol.AMENDMENT.read_text(encoding="utf-8"))
    assert record["status"] == "registered" and record["frozen_config_a"] == "25685b84dd83f65c"
    assert {f"{k[0]}/{k[1]}" if k[1] else k[0]: v for k, v in protocol.MAPPING.items()} == record["mapping"]["cicids2017_improved"]
    assert record["scenario_bank"]["manifest_sha256"] == protocol.BANK_MANIFEST_SHA256
    assert tuple(record["scope"]["held_out_families"]) == protocol.HELD_OUT_FAMILIES
    assert tuple(record["scope"]["seeds"]) == protocol.FOLD_SEEDS
    assert tuple(record["selection"]["candidates"]) == protocol.RATIOS and record["selection"]["default"] == protocol.RATIOS[0]
    compute = record["compute"]
    assert (compute["approved_planning_budget_cpu_hours"], compute["in_stage_stop"], compute["hard_stop"]) == (
        protocol.APPROVED_PLANNING_BUDGET, protocol.IN_STAGE_STOP, protocol.HARD_STOP)
    assert sum(protocol.STAGE_CEILINGS.values()) == pytest.approx(compute["worst_case_cpu_hours"] - 3.24, abs=0.06)
    assert "6" not in protocol.STAGES and "excluded" in record["perturbation_arm"]
    groups = record["analysis"]["fold_groups"]
    assert tuple(groups["two_family"]["outer"]) == protocol.FOLD_GROUPS["two_family"]
    assert tuple(groups["single_family"]["outer"]) == protocol.FOLD_GROUPS["single_family"]


def test_a_failed_fit_still_records_its_cpu(tmp_path):
    ledger = Ledger(tmp_path / "ledger.csv")
    with pytest.raises(ValueError):
        with ledger.fit("1", "fails"):
            raise ValueError("boom")
    assert [r["label"] for r in ledger.rows] == ["fails"] and (tmp_path / "ledger.csv").exists()
