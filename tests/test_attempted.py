"""Secondary metric for the improved CICIDS2017: "Attempted" flows scored as benign test traffic."""

import dataclasses
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from aegis.config import AutoencoderConfig, DatasetConfig, RandomForestConfig, load_config
from aegis.data.dataset import BENIGN, Dataset, remove_duplicates
from aegis.data.improved import (
    AttemptedRows,
    DatasetWithAttempted,
    load_attempted,
    load_cicids2017_improved,
    load_with_attempted,
)
from aegis.data.loaders import generate_synthetic, load_dataset
from aegis.data.splits import make_partition, seen_fold
from aegis.evaluation.metrics import precision_at_prevalence
from aegis.experiments import baseline
from aegis.experiments.baseline import (
    FoldStore,
    _AttemptedScores,
    _score_attempted,
    _score_rows,
    prepare_datasets,
    run,
    summarize,
)
from test_improved import FEATURES, write_release

ROOT = Path(__file__).resolve().parents[1]
SECONDARY = ["n_attempted", "n_attempted_dup_train", "n_attempted_dup_train_alarms", "attempted_share",
             "attempted_alarm_rate", "realized_fpr_with_attempted"]


def test_attempted_rows_come_apart_with_the_same_columns(tmp_path):
    folder = write_release(tmp_path / "improved", extra_index=True)
    primary, attempted = load_with_attempted(folder, ("Dst Port",))
    pd.testing.assert_frame_equal(primary.X, load_cicids2017_improved(folder, ("Dst Port",)).X)
    assert list(attempted.X.columns) == list(primary.X.columns) == ["Protocol", *FEATURES]
    assert list(attempted.category) == [0, 6, 2, 1]  # Tuesday to Friday, in file order.
    assert list(attempted.family) == ["brute_force", "dos", "web_attack", "bot"]
    assert attempted.X["Flow Duration"].tolist() == [3.0, 3.0, 3.0, 4.0]  # Their own rows' values.
    pd.testing.assert_frame_equal(load_attempted(folder, ("Dst Port",)).X, attempted.X)


def test_prepared_improved_dataset_carries_deduplicated_attempted_rows(tmp_path):
    folder = write_release(tmp_path / "improved")
    dataset_config = DatasetConfig(kind="cicids2017_improved", path=str(folder), drop_columns=("Dst Port",))
    config = dataclasses.replace(load_config(ROOT / "configs" / "smoke.yaml"), datasets=(dataset_config,))
    [ds], cleaning = prepare_datasets(config)
    expected, expected_stats = remove_duplicates(load_dataset(dataset_config))
    assert isinstance(ds, DatasetWithAttempted)
    pd.testing.assert_frame_equal(ds.X, expected.X)
    assert list(ds.family) == list(expected.family)
    # Three attempted rows share the features (3.0, ...), so two are repeats.
    assert cleaning["cicids2017_improved"] == {**expected_stats, "attempted_rows_before": 4,
                                               "attempted_rows_after": 2}
    assert len(ds.attempted) == 2


class StubModel:
    """Scores are the ``s`` column, the same for every scorer; validation benign scores give 0.5."""

    val_benign_scores = {name: np.full(100, 0.5) for name in ("rf", "ae", "fused")}

    def scores(self, X):
        return {name: X["s"].to_numpy(dtype=float) for name in ("rf", "ae", "fused")}


def test_secondary_columns_on_a_hand_checked_case():
    config = dataclasses.replace(load_config(ROOT / "configs" / "smoke.yaml"), target_fprs=(0.01,),
                                 attack_prevalences=(0.01,))
    ds = Dataset("toy", pd.DataFrame({"s": [0.1, 0.2, 0.3, 0.9, 0.8, 0.95]}), [BENIGN] * 4 + ["dos"] * 2)
    rows = AttemptedRows(pd.DataFrame({"s": [0.6, 0.1]}), [0, 3], ["dos", "dos"])
    ds = DatasetWithAttempted(ds.name, ds.X, ds.family, attempted=rows)
    train = np.array([1])  # Holds the row with s = 0.2 only.
    hashes = baseline._hash_rows(ds.X)
    attempted = _score_attempted(StubModel(), ds, train, hashes)
    assert attempted.share == pytest.approx(2 / 6)  # Two attempted rows, four benign rows.
    assert attempted.copies_training.tolist() == [False, False]
    attempted = dataclasses.replace(attempted, copies_training=np.array([True, False]))

    test = np.arange(6)
    plain = _score_rows(StubModel(), 1.0, ds, ds, test, "seen", ["all_attacks"], config, 0)
    secondary = _score_rows(StubModel(), 1.0, ds, ds, test, "seen", ["all_attacks"], config, 0, attempted)
    assert len(plain) == len(secondary) == 3
    for before, after in zip(plain, secondary):
        assert {k: after[k] for k in before} == before  # Primary columns untouched.
        assert set(after) - set(before) == {*SECONDARY, "precision_prev_0.01_with_attempted"}
        assert after["recall"] == 1.0 and after["realized_fpr"] == 0.25
        assert after["n_attempted"] == 2 and after["attempted_alarm_rate"] == 0.5
        assert after["n_attempted_dup_train"] == 1 and after["n_attempted_dup_train_alarms"] == 1
        fpr = (2 / 3) * 0.25 + (1 / 3) * 0.5
        assert after["realized_fpr_with_attempted"] == pytest.approx(fpr)
        assert after["precision_prev_0.01_with_attempted"] == pytest.approx(
            precision_at_prevalence(1.0, fpr, 0.01)
        )


@pytest.fixture(scope="module")
def synthetic_runs(tmp_path_factory):
    """The same run with and without attempted rows, recording every frame the model is fitted on."""
    config = dataclasses.replace(
        load_config(ROOT / "configs" / "smoke.yaml"),
        datasets=(DatasetConfig(kind="synthetic", name="synthetic_a", seed=11),),
        seeds=(0,),
        cross_dataset=False,
        rf=RandomForestConfig(n_estimators=10, max_depth=8, min_samples_leaf=2, n_jobs=1),
        autoencoder=AutoencoderConfig(hidden=(16,), latent=4, epochs=2, batch_size=256,
                                      learning_rate=0.001, patience=2, device="cpu"),
    )
    ds, cleaning = remove_duplicates(generate_synthetic("synthetic_a", seed=11))
    rng = np.random.default_rng(3)
    fresh = pd.DataFrame(rng.lognormal(0.0, 0.4, size=(300, 12)).astype(np.float32), columns=ds.X.columns)
    fresh.iloc[:100, :3] *= 30.0  # Some look like the "scan" family.
    copies = np.array([0, 1, 2])
    rows = AttemptedRows(pd.concat([fresh, ds.X.iloc[copies]], ignore_index=True),
                         np.zeros(303, dtype=int), np.array(["scan"] * 303, dtype=object))
    with_attempted = DatasetWithAttempted(ds.name, ds.X, ds.family, attempted=rows)

    fitted = []
    original_fit = baseline.RFAEBaseline.fit

    def recording_fit(self, X_train, y_train, X_val, y_val, *args, **kwargs):
        fitted.append((X_train, X_val))
        return original_fit(self, X_train, y_train, X_val, y_val, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(baseline.RFAEBaseline, "fit", recording_fit)
        out = tmp_path_factory.mktemp("attempted")
        plain = run(config, out / "plain", prepared=([ds], {ds.name: cleaning}), log=lambda _: None)
        secondary = run(config, out / "secondary", prepared=([with_attempted], {ds.name: cleaning}),
                        log=lambda _: None)
    return ds, rows, copies, fitted, plain, secondary, out


def test_attempted_rows_never_reach_training(synthetic_runs):
    ds, rows, _, fitted, *_ = synthetic_runs
    fresh = set(baseline._hash_rows(rows.X.iloc[:300]))
    assert len(fitted) == 10  # Five folds, twice.
    for X_train, X_val in fitted:
        for frame in (X_train, X_val):
            assert frame.index.max() < len(ds.X)  # Rows of the primary frame only.
            assert not fresh & set(baseline._hash_rows(frame))


def test_primary_results_identical_and_secondary_columns_added(synthetic_runs):
    ds, rows, copies, _, plain, secondary, _ = synthetic_runs
    assert not set(SECONDARY) & set(plain.columns)  # Datasets without attempted rows are unaffected.
    pd.testing.assert_frame_equal(plain.drop(columns="fit_seconds"),
                                  secondary[plain.columns].drop(columns="fit_seconds"))
    assert (secondary["n_attempted"] == 303).all()
    assert secondary["attempted_share"].iloc[0] == pytest.approx(303 / (303 + (ds.family == BENIGN).sum()))
    # The three copied rows count as duplicates of training when their originals are trained on.
    fold = seen_fold(make_partition(ds.family, 0, 0.2, 0.2), ds.family, 5000, 0)
    seen = secondary[secondary["fold"] == "seen"]
    assert (seen["n_attempted_dup_train"] == np.isin(copies, fold.train).sum()).all()
    assert secondary["realized_fpr_with_attempted"].between(0, 1).all()


def test_old_fold_files_without_secondary_columns_still_load(synthetic_runs):
    *_, plain, secondary, out = synthetic_runs
    store = FoldStore(out / "mixed")
    store.save("old", 0, "seen", plain.head(3).to_dict("records"))
    store.save("new", 0, "seen", secondary.head(3).assign(dataset="new").to_dict("records"))
    loaded = store.load_all()
    assert loaded.loc[loaded["dataset"] == "old", "attempted_alarm_rate"].isna().all()
    assert loaded.loc[loaded["dataset"] == "new", "attempted_alarm_rate"].notna().all()
    summary = summarize(loaded, samples=50)
    assert "n_attempted_mean" not in summary.columns and "attempted_alarm_rate_mean" in summary.columns
