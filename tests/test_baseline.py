import dataclasses
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from aegis.config import AutoencoderConfig, DatasetConfig, RandomForestConfig, load_config
from aegis.data.dataset import BENIGN, remove_duplicates
from aegis.data.loaders import generate_synthetic
from aegis.data.splits import holdout_fold, make_partition, seen_fold
from aegis.evaluation.metrics import threshold_at_fpr
from aegis.experiments.baseline import phase1_gate, run
from aegis.models.baseline import (
    RandomForestBaseline, RFAEBaseline, TailCalibrator, build_preprocessor, fit_forest, forest_probability,
)
from aegis.provenance import file_sha256

ROOT = Path(__file__).resolve().parents[1]


def test_preprocessor_statistics_depend_only_on_training_rows():
    train = pd.DataFrame({"a": [1.0, 2.0, np.nan, 4.0] * 10, "p": ["tcp"] * 40})
    probe = pd.DataFrame({"a": [3.0, np.nan], "p": ["never-seen", "tcp"]})
    first = build_preprocessor(["a"], ["p"]).fit(train).transform(probe)
    extended = pd.concat([train, pd.DataFrame({"a": [1e9] * 5, "p": ["udp"] * 5})])
    second = build_preprocessor(["a"], ["p"]).fit(extended).transform(probe)
    assert first.shape[0] == 2
    assert np.isfinite(first).all()
    assert not np.array_equal(first[:, 0], second[:, 0])  # Statistics follow the fit data.


def test_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("datasets: []\nunknown_option: 1\n", encoding="utf-8")
    with pytest.raises(TypeError):
        load_config(path)


@pytest.fixture(scope="module")
def fitted():
    config = load_config(ROOT / "configs" / "smoke.yaml")
    ds, _ = remove_duplicates(generate_synthetic(seed=5))
    part = make_partition(ds.family, seed=0)
    fold = holdout_fold(part, ds.family, "exfil", 5000, 0)
    model = RFAEBaseline(config.rf, config.autoencoder, 0).fit(
        ds.X.iloc[fold.train], ds.y[fold.train], ds.X.iloc[fold.val], ds.y[fold.val], ds.numeric
    )
    return ds, fold, part, model, config


def test_calibration_scores_come_from_validation_benign_only(fitted):
    ds, fold, _, model, _ = fitted
    n_benign_val = int((ds.family[fold.val] == BENIGN).sum())
    assert all(len(v) == n_benign_val for v in model.val_benign_scores.values())


def test_validation_threshold_holds_on_unseen_benign_traffic(fitted):
    ds, fold, _, model, _ = fitted
    scores = model.scores(ds.X.iloc[fold.test])["fused"]
    threshold = threshold_at_fpr(model.val_benign_scores["fused"], 0.01)
    assert (scores[ds.family[fold.test] == BENIGN] > threshold).mean() < 0.03


def test_fused_score_detects_a_family_absent_from_training(fitted):
    # The cluster is far from benign traffic, so the anomaly channel should catch it.
    ds, fold, _, model, _ = fitted
    scores = model.scores(ds.X.iloc[fold.test])
    threshold = threshold_at_fpr(model.val_benign_scores["fused"], 0.01)
    assert (scores["fused"][ds.family[fold.test] == "exfil"] > threshold).mean() > 0.8


def test_tail_calibration_is_scale_free_and_ordered():
    benign = np.arange(1000, dtype=float)
    calibrator = TailCalibrator(benign)
    rescaled = TailCalibrator(benign * 1000 - 7)
    probe = np.array([500.0, 990.0, 999.0])
    assert calibrator(probe) == pytest.approx(rescaled(probe * 1000 - 7))
    values = calibrator(np.array([-5.0, 500.0, 990.0, 999.0, 2000.0, 4000.0]))
    assert values[0] == pytest.approx(0.0)
    assert np.all(np.diff(values) > 0)


def test_long_tailed_scorer_cannot_mask_the_other_scorer():
    rng = np.random.default_rng(0)
    long_tail = TailCalibrator(np.exp(rng.normal(0, 4, 5000)))
    well_behaved = TailCalibrator(rng.normal(0, 1, 5000))
    # An extreme value on the well-behaved scorer must outrank a typical value on the other.
    assert well_behaved(np.array([6.0]))[0] > long_tail(np.array([1.0]))[0]


def test_end_to_end_run_writes_all_outputs(tmp_path):
    config = load_config(ROOT / "configs" / "smoke.yaml")
    results = run(config, tmp_path / "run")

    for name in ("results.csv", "summary.csv", "degradation.csv", "manifest.json"):
        assert (tmp_path / "run" / name).stat().st_size > 0

    on_disk = pd.read_csv(tmp_path / "run" / "results.csv")
    assert len(on_disk) == len(results)
    assert set(results["scorer"]) == {"rf", "ae", "fused"}
    assert results["recall"].between(0, 1).all()
    assert (results["fold"] == "cross:synthetic_a->synthetic_b").any()

    degradation = pd.read_csv(tmp_path / "run" / "degradation.csv")
    assert set(degradation["eval_family"]) == {"scan", "flood", "exfil", "beacon"}
    assert (degradation["n"] == 3).all()
    # Removing a family from training should cost the supervised forest recall.
    rf = degradation[(degradation["scorer"] == "rf") & (degradation["target_fpr"] == 0.01)]
    assert (rf["mean_diff"] > 0).all()

    # Nothing is refitted when the same run is started again.
    before = {p.name: p.stat().st_mtime_ns for p in (tmp_path / "run" / "folds").iterdir()}
    messages = []
    rerun = run(config, tmp_path / "run", log=messages.append)
    assert messages == []
    assert len(rerun) == len(results)
    after = {p.name: p.stat().st_mtime_ns for p in (tmp_path / "run" / "folds").iterdir()}
    assert before == after

    with pytest.raises(ValueError, match="different settings"):
        run(dataclasses.replace(config, min_family_count=101), tmp_path / "run")


def test_interrupted_run_continues_and_seeds_can_be_added(tmp_path):
    config = dataclasses.replace(
        load_config(ROOT / "configs" / "smoke.yaml"), seeds=(0,), cross_dataset=False
    )
    out = tmp_path / "run"
    run(config, out)
    folds = sorted((out / "folds").glob("*.csv"))
    folds[-1].unlink()  # A fold that never finished.

    messages = []
    run(config, out, log=messages.append)
    assert len(messages) == 1

    results = run(dataclasses.replace(config, seeds=(0, 1)), out, log=lambda _: None)
    assert set(results["seed"]) == {0, 1}


@pytest.fixture(scope="module")
def finished_run(tmp_path_factory):
    config = dataclasses.replace(
        load_config(ROOT / "configs" / "smoke.yaml"),
        datasets=(DatasetConfig(kind="synthetic", name="synthetic_a", seed=11, path="old/place"),),
        seeds=(0,),
        cross_dataset=False,
    )
    out = tmp_path_factory.mktemp("finished") / "run"
    run(config, out, log=lambda _: None)
    return config, out


def test_new_runtime_resumes_and_is_recorded(finished_run):
    config, out = finished_run
    moved = dataclasses.replace(
        config,
        datasets=(dataclasses.replace(config.datasets[0], path="new/place"),),
        rf=RandomForestConfig(**{**dataclasses.asdict(config.rf), "n_jobs": 1}),
        autoencoder=AutoencoderConfig(
            **{**dataclasses.asdict(config.autoencoder), "hidden": tuple(config.autoencoder.hidden), "device": "cpu:0"}
        ),
    )
    messages = []
    run(moved, out, log=messages.append)
    assert len(messages) == 1 and "device changed from cpu to cpu:0" in messages[0]

    first, second = json.loads((out / "manifest.json").read_text(encoding="utf-8"))["sessions"][:2]
    assert (first["ae_device"], first["rf_n_jobs"]) == ("cpu", config.rf.n_jobs)
    assert (second["ae_device"], second["rf_n_jobs"]) == ("cpu:0", 1)
    assert second["dataset_paths"] == {"synthetic_a": "new/place"}
    assert first["folds_already_done"] == 0 and second["folds_already_done"] > 0


def test_changed_experiment_settings_are_refused(finished_run):
    config, out = finished_run
    with pytest.raises(ValueError, match="different settings, code or data"):
        run(dataclasses.replace(config, max_train_per_family=4000), out)
    deeper = AutoencoderConfig(**{**dataclasses.asdict(config.autoencoder), "latent": 4})
    with pytest.raises(ValueError, match="different settings, code or data"):
        run(dataclasses.replace(config, autoencoder=deeper), out)


def test_changed_code_is_refused(finished_run, monkeypatch):
    config, out = finished_run
    monkeypatch.setattr("aegis.experiments.baseline.source_hash", lambda: "another-version")
    with pytest.raises(ValueError, match="different settings, code or data"):
        run(config, out)


def test_changed_data_is_refused(finished_run):
    config, out = finished_run
    fewer, cleaning = remove_duplicates(generate_synthetic("synthetic_a", seed=11, n_benign=3000))
    with pytest.raises(ValueError, match="different settings, code or data"):
        run(config, out, prepared=([fewer], {"synthetic_a": cleaning}))


@pytest.mark.parametrize(
    "contents",
    ['{"config": {}, "git": "ce18961"}', "{not json", "[1, 2]", ""],
    ids=["older_format", "corrupt", "wrong_shape", "empty"],
)
def test_unusable_manifest_is_refused_clearly(tmp_path, contents):
    (tmp_path / "manifest.json").write_text(contents, encoding="utf-8")
    config = dataclasses.replace(
        load_config(ROOT / "configs" / "smoke.yaml"), seeds=(0,), cross_dataset=False
    )
    with pytest.raises(ValueError, match="Use a new output folder"):
        run(config, tmp_path)
    assert (tmp_path / "manifest.json").read_text(encoding="utf-8") == contents


def test_source_checksums_refuse_changed_files_but_allow_a_moved_folder(tmp_path):
    folder = tmp_path / "first"
    folder.mkdir()
    (folder / "day1.csv").write_text("a,Label\n1,BENIGN\n", encoding="utf-8")
    data = remove_duplicates(generate_synthetic("cicids2017", seed=11))
    prepared = ([data[0]], {"cicids2017": data[1]})

    def config_for(path):
        return dataclasses.replace(
            load_config(ROOT / "configs" / "smoke.yaml"),
            datasets=(DatasetConfig(kind="cicids2017", path=str(path)),),
            seeds=(0,),
            cross_dataset=False,
        )

    out = tmp_path / "run"
    run(config_for(folder), out, prepared=prepared, log=lambda _: None)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["identity"]["data"]["source_sha256"] == {
        "cicids2017": {"day1.csv": file_sha256(folder / "day1.csv")}
    }

    moved = folder.rename(tmp_path / "second")
    run(config_for(moved), out, prepared=prepared, log=lambda _: None)

    # The same row counts with one changed value: only a checksum can see this.
    (moved / "day1.csv").write_text("a,Label\n2,BENIGN\n", encoding="utf-8")
    with pytest.raises(ValueError, match="different settings, code or data"):
        run(config_for(moved), out, prepared=prepared)


def test_file_sha256_matches_a_whole_file_hash(tmp_path):
    path = tmp_path / "data.csv"
    path.write_bytes(b"x" * 5000)
    assert file_sha256(path, chunk_size=64) == hashlib.sha256(b"x" * 5000).hexdigest()


def test_phase1_gate_reports_missing_measurements():
    config = dataclasses.replace(load_config(ROOT / "configs" / "smoke.yaml"), seeds=(0, 1))
    ds, _ = remove_duplicates(generate_synthetic(name="synthetic_a", seed=1))
    results = pd.DataFrame(
        {
            "dataset": ["synthetic_a"] * 2,
            "test_dataset": ["synthetic_a"] * 2,
            "fold": ["holdout:scan"] * 2,
            "eval_family": ["scan"] * 2,
            "seed": [0, 1],
        }
    )
    gate = phase1_gate(results, [ds], config).set_index("family")
    assert bool(gate.loc["scan", "complete"]) is True
    assert bool(gate.loc["flood", "complete"]) is False


def forest_and_rows(n_jobs=4):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(3000, 8)).astype(np.float32)
    y = (X[:, 0] + 0.5 * X[:, 1] + rng.normal(scale=0.8, size=3000) > 0).astype(int)
    return fit_forest(RandomForestConfig(n_estimators=40, max_depth=8, n_jobs=n_jobs), 0, X[:2000], y[:2000]), X[2000:]


def test_forest_scores_are_identical_for_every_worker_count_and_repeat():
    # predict_proba with several workers adds trees in thread order, so its last digits vary between calls.
    forest, X = forest_and_rows()
    serial = forest.set_params(n_jobs=1).predict_proba(X)[:, 1]
    for n_jobs in (1, 2, 3, 8, -1):
        for _ in range(3):
            assert np.array_equal(forest_probability(forest, X, n_jobs), serial), n_jobs
    assert np.array_equal(forest_probability(forest, X[:5], 8), serial[:5])  # Fewer rows than blocks.
    assert forest_probability(forest, X[:0], 4).shape == (0,)


def test_forest_fit_does_not_depend_on_the_worker_count():
    one, X = forest_and_rows(n_jobs=1)
    eight, _ = forest_and_rows(n_jobs=8)
    assert np.array_equal(forest_probability(one, X), forest_probability(eight, X))


def test_baseline_scores_do_not_depend_on_the_worker_count():
    ds = generate_synthetic(seed=1)
    fold = holdout_fold(make_partition(ds.family, 0, 0.2, 0.2), ds.family, "exfil", 2000, 0)
    y = (ds.family[fold.train] != BENIGN).astype(int)
    val_benign = fold.val[ds.family[fold.val] == BENIGN]
    numeric = [c for c in ds.X.columns if c not in ds.categorical]
    scores = []
    for n_jobs in (1, 8):
        model = RandomForestBaseline(RandomForestConfig(n_estimators=30, max_depth=8, n_jobs=n_jobs), seed=0).fit(
            ds.X.iloc[fold.train], y, ds.X.iloc[val_benign], numeric, ds.categorical)
        scores.append((model.val_benign_scores, model.scores(ds.X.iloc[fold.test])))
    assert all(np.array_equal(a, b) for a, b in zip(*scores))
