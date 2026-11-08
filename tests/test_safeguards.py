import dataclasses
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from aegis.config import BaselineConfig, DatasetConfig, RandomForestConfig, load_config
from aegis.data import external, loaders
from aegis.data.loaders import generate_synthetic, load_dataset
from aegis.data.splits import make_partition
from aegis import frozen
from aegis.experiments import selection
from aegis.experiments.selection import benign_halves, fit_rf_only, nested_rows, pair_rows, select

ROOT = Path(__file__).resolve().parents[1]


def small_config() -> BaselineConfig:
    return BaselineConfig(
        datasets=(DatasetConfig(kind="synthetic", name="synthetic_a", seed=3),),
        seeds=(0,), max_train_per_family=2000, min_family_count=100, bootstrap_samples=100,
        rf=RandomForestConfig(n_estimators=10, max_depth=6, n_jobs=1),
    )


def poisoned(ds, rows, rng):
    """A copy whose given rows carry meaningless features and shuffled labels."""
    X = ds.X.copy()
    X.iloc[rows] = rng.normal(1e6, 1.0, size=(len(rows), X.shape[1])).astype(X.dtypes.iloc[0])
    family = ds.family.copy()
    family[rows] = rng.permutation(family[rows])
    return type(ds)(ds.name, X, family, ds.categorical)


def test_nested_selection_never_reads_the_outer_test_rows():
    ds, config = generate_synthetic("synthetic_a", 3), small_config()
    partition = make_partition(ds.family, 0, config.val_fraction, config.test_fraction)
    clean = pd.DataFrame(nested_rows(ds, partition.train, partition.val, config, 0, fit_rf_only, ("rf",)))
    dirty_ds = poisoned(ds, partition.test, np.random.default_rng(1))
    dirty = pd.DataFrame(nested_rows(dirty_ds, partition.train, partition.val, config, 0, fit_rf_only, ("rf",)))
    pd.testing.assert_frame_equal(clean, dirty)


def test_inner_folds_drop_both_families_and_use_validation_rows_only():
    ds, config = generate_synthetic("synthetic_a", 3), small_config()
    partition = make_partition(ds.family, 0, config.val_fraction, config.test_fraction)
    seen = {}

    def spy(ds_, train, threshold_benign, config_, seed):
        seen["train"], seen["threshold"] = train, threshold_benign
        return fit_rf_only(ds_, train, threshold_benign, config_, seed)

    rows = pd.DataFrame(pair_rows(("scan", "flood"), partition.train, partition.val, ds, config, 0, spy, ("rf",)))
    assert not set(ds.family[seen["train"]]) & {"scan", "flood"}
    assert set(seen["train"]) <= set(partition.train)
    assert set(seen["threshold"]) <= set(partition.val) and set(ds.family[seen["threshold"]]) == {"benign"}
    # One fit serves both directions.
    assert set(zip(rows["outer_family"], rows["inner_family"])) == {("scan", "flood"), ("flood", "scan")}
    threshold_half, eval_half = benign_halves(partition.val, ds.family, 0)
    assert not set(threshold_half) & set(eval_half)


def test_selection_rule_takes_the_best_mean_and_breaks_ties_by_order():
    rows = pd.DataFrame(
        [{"dataset": "d", "seed": 0, "outer_family": "f", "inner_family": g, "candidate": c, "target_fpr": 0.01,
          "inner_recall": r} for g, c, r in [("a", "rf", 0.5), ("b", "rf", 0.7), ("a", "ae", 0.6), ("b", "ae", 0.6)]]
        + [{"dataset": "d", "seed": 0, "outer_family": "g", "inner_family": "a", "candidate": c, "target_fpr": 0.01,
            "inner_recall": 0.4} for c in ("rf", "ae")]
    )
    chosen = select(rows, 0.01, ("rf", "ae")).set_index("outer_family")["selected"]
    assert chosen["f"] == "rf"  # 0.6 against 0.6: the first listed wins.
    assert chosen["g"] == "rf"
    rows.loc[(rows.outer_family == "f") & (rows.candidate == "ae") & (rows.inner_family == "b"), "inner_recall"] = 0.9
    assert select(rows, 0.01, ("rf", "ae")).set_index("outer_family").loc["f", "selected"] == "ae"


def test_a_challenger_needs_a_majority_of_inner_wins_not_just_a_higher_mean():
    def frame(ae):
        rf = [0.5, 0.5, 0.5]
        return pd.DataFrame([{"dataset": "d", "seed": 0, "outer_family": "f", "inner_family": g, "candidate": c,
                              "target_fpr": 0.01, "inner_recall": r}
                             for c, values in (("rf", rf), ("ae", ae)) for g, r in zip("abc", values)])
    pick = lambda ae: select(frame(ae), 0.01, ("rf", "ae")).loc[0, "selected"]
    assert pick([0.95, 0.45, 0.45]) == "rf"  # Higher mean from one large win: 1 of 3 is no majority.
    assert pick([0.6, 0.5, 0.45]) == "rf"  # A tie on b is no win, so 1 of 3.
    assert pick([0.6, 0.6, 0.2]) == "rf"  # 2 of 3 wins, but the mean is lower.
    assert pick([0.6, 0.6, 0.45]) == "ae"  # 2 of 3 wins and a higher mean.
    assert select(frame([0.6, 0.6, 0.45]), 0.01, ("rf", "ae")).loc[0, "inner_wins_ae"] == 2


def test_a_pair_with_no_attack_training_rows_is_skipped_and_selects_nothing():
    ds = generate_synthetic("synthetic_a", 3)
    keep = np.isin(ds.family.astype(str), ["benign", "scan", "flood"])
    ds = type(ds)(ds.name, ds.X[keep], ds.family[keep])
    config = small_config()
    partition = make_partition(ds.family, 0, config.val_fraction, config.test_fraction)
    rows = pd.DataFrame(nested_rows(ds, partition.train, partition.val, config, 0, fit_rf_only, ("rf",)))
    assert rows["inner_recall"].isna().all() and (rows["skipped"] != "").all()
    assert set(select(rows, 0.01, ("rf",))["selected"]) == {"none"}


def test_selection_run_writes_one_choice_per_outer_family_and_resumes(tmp_path):
    config = small_config()
    selected = selection.run(config, tmp_path, fit=fit_rf_only, candidates=("rf",), log=lambda m: None)
    assert len(selected) == 4 and set(selected["n_inner_families"]) == {3}
    lines = []
    selection.run(config, tmp_path, fit=fit_rf_only, candidates=("rf",), log=lines.append)
    assert not [line for line in lines if line.startswith("[")]


def test_the_baseline_config_matches_the_frozen_config_a():
    config = load_config(ROOT / "configs" / "baseline.yaml")
    frozen.verify_config_a(config)
    frozen.verify_config_a(dataclasses.replace(config, rf=dataclasses.replace(config.rf, n_jobs=1)))  # Machine only.
    changed = dataclasses.replace(config, rf=dataclasses.replace(config.rf, n_estimators=200))
    with pytest.raises(ValueError, match="n_estimators"):
        frozen.verify_config_a(changed)


def test_a_code_change_breaks_the_frozen_identity(monkeypatch):
    config = load_config(ROOT / "configs" / "baseline.yaml")
    altered = json.loads(json.dumps(frozen.FROZEN))
    altered["implementation_sha256"]["models/baseline.py"] = "0" * 64
    monkeypatch.setattr(frozen, "FROZEN", altered)
    with pytest.raises(ValueError, match="models/baseline.py"):
        frozen.verify_config_a(config)


def registration(**changes) -> dict:
    base = {
        "dataset": "cse_cic_ids2018", "release": "to be confirmed", "frozen_config_a": frozen.frozen_digest(),
        "registered_utc": "2026-11-08T00:00:00Z", "registered_by": "owner", "attempted_handling": "benign",
        "inspection_allowed": "headers, row counts, label counts", "primary_metric": "raw_recall",
        "evaluation_views": ["raw"], "comparisons": ["config_a"], "shortcut_rule": "as in v2",
    }
    return {**base, **changes}


def test_external_set_refuses_without_preregistration_and_logs_the_attempt(tmp_path):
    config = load_config(ROOT / "configs" / "baseline.yaml")
    path = tmp_path / "prereg.json"
    with pytest.raises(PermissionError, match="No pre-registration"):
        external.guarded_load(path, "cse_cic_ids2018", config, lambda: "data", "test")
    log = [json.loads(line) for line in external.access_log_path(path).read_text().splitlines()]
    assert log[0]["allowed"] is False


@pytest.mark.parametrize("change, message", [
    ({"frozen_config_a": "deadbeef"}, "different frozen Config A"),
    ({"dataset": "unsw_nb15"}, "not cse_cic_ids2018"),
    ({"attempted_handling": ""}, "missing"),
])
def test_external_set_refuses_a_mismatched_preregistration(tmp_path, change, message):
    config = load_config(ROOT / "configs" / "baseline.yaml")
    path = tmp_path / "prereg.json"
    path.write_text(json.dumps(registration(**change)), encoding="utf-8")
    called = []
    with pytest.raises(PermissionError, match=message):
        external.guarded_load(path, "cse_cic_ids2018", config, lambda: called.append(1), "test")
    assert not called


def test_external_set_refuses_a_config_that_is_not_config_a(tmp_path):
    config = load_config(ROOT / "configs" / "baseline.yaml")
    path = tmp_path / "prereg.json"
    path.write_text(json.dumps(registration()), encoding="utf-8")
    changed = dataclasses.replace(config, min_family_count=100)
    with pytest.raises(ValueError, match="min_family_count"):
        external.guarded_load(path, "cse_cic_ids2018", changed, lambda: "data", "test")


def test_external_set_loads_once_registered_and_records_it(tmp_path):
    config = load_config(ROOT / "configs" / "baseline.yaml")
    path = tmp_path / "prereg.json"
    path.write_text(json.dumps(registration()), encoding="utf-8")
    assert external.guarded_load(path, "cse_cic_ids2018", config, lambda: "data", "final test") == "data"
    entry = json.loads(external.access_log_path(path).read_text().splitlines()[-1])
    assert entry["allowed"] is True and entry["purpose"] == "final test" and entry["preregistration_sha256"]


def test_the_ordinary_loader_refuses_the_external_set():
    with pytest.raises(PermissionError, match="guarded_load"):
        load_dataset(DatasetConfig(kind="cse_cic_ids2018", path="anywhere"))


def test_selection_notebook_is_current_and_runs_on_small_csv_files(tmp_path, monkeypatch):
    # If the first assertion fails, run: .venv/bin/python notebooks/build_selection_notebook.py
    import importlib.util
    import zipfile

    import nbformat
    from nbclient import NotebookClient

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    notebook_path = ROOT / "notebooks" / "selection_check.ipynb"
    builder = load("build_notebook", ROOT / "notebooks" / "build_notebook.py")
    assert f"SOURCE_VERSION = '{builder.source_hash()}'" in notebook_path.read_text(encoding="utf-8")
    fixtures = load("test_notebook_fixtures", ROOT / "tests" / "test_notebook.py")
    rng = np.random.default_rng(0)
    fixtures.cicids_fixture(tmp_path / "data" / "CNS2022" / "CICIDS2017", rng)
    fixtures.unsw_fixture(tmp_path / "data" / "UNSW", rng)
    output = tmp_path / "results" / "selection_check"
    monkeypatch.setenv("AEGIS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(output))
    monkeypatch.setenv("AEGIS_SEEDS", "0")
    notebook = nbformat.read(notebook_path, as_version=4)
    assert all(not cell.get("outputs") for cell in notebook.cells if cell.cell_type == "code")
    NotebookClient(notebook, timeout=900, kernel_name="python3",
                   resources={"metadata": {"path": str(tmp_path)}}).execute()
    text = "\n".join(str(o.get("text", "")) for c in notebook.cells if c.cell_type == "code" for o in c.outputs)
    assert "Pipeline check passed" in text and "Settings and code match the frozen Config A" in text
    assert "Nested selection chose rf in" in text
    with zipfile.ZipFile(output / "aegis_selection_results.zip") as bundle:
        assert set(bundle.namelist()) == {"manifest.json", "inner_results.csv", "selections.csv"}
