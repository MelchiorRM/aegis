import importlib.util
import json
import zipfile
from pathlib import Path

import nbformat
import numpy as np
import pandas as pd
import pytest
from nbclient import NotebookClient

from aegis.config import BaselineConfig, DatasetConfig, RandomForestConfig
from aegis.data.dataset import Dataset
from aegis.data.splits import Fold
from aegis.experiments.artifacts import (
    REFERENCE,
    Treatment,
    build_raw_rows,
    evaluate_raw,
    missingness_frame,
    run,
    signatures,
    training_rows,
    treated_features,
    treatments_for,
)
from aegis.models.baseline import RandomForestBaseline

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "artifact_resistance.ipynb"


def cicids_like() -> Dataset:
    X = pd.DataFrame(
        {
            "Flow Duration": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
            "Total Fwd Packets": [3.0, 3.0, 3.0, 9.0, 8.0, 7.0],
            "Init_Win_bytes_forward": [-1.0, 8.0, 8.0, 8.0, 5.0, -1.0],
            "Init_Win_bytes_backward": [2.0, 2.0, 2.0, 2.0, 2.0, 2.0],
            "Flow Bytes/s": [np.nan, 1.0, 1.0, 1.0, 1.0, 1.0],
        }
    )
    family = np.array(["benign", "web", "dos", "dos", "benign", "benign"], dtype=object)
    return Dataset("cicids2017", X, family)


def test_matching_ignores_timing_and_removes_only_training_attacks():
    ds = cicids_like()
    # Rows 1 and 2 differ only in Flow Duration. Row 0 has another window value.
    found = signatures(ds)
    assert found[1] == found[2] != found[3]

    fold = Fold("holdout:web", np.array([0, 2, 3, 4, 5]), np.array([], dtype=int), np.array([1]), "web")
    assert training_rows(fold, ds, Treatment(REFERENCE), found).tolist() == [0, 2, 3, 4, 5]
    assert training_rows(fold, ds, Treatment("x", remove_signatures=True), found).tolist() == [0, 3, 4, 5]


def test_matching_keeps_benign_rows_with_the_same_signature():
    ds = cicids_like()
    ds.family[2] = "benign"
    fold = Fold("holdout:web", np.array([0, 2, 3, 4, 5]), np.array([], dtype=int), np.array([1]), "web")
    assert 2 in training_rows(fold, ds, Treatment("x", remove_signatures=True), signatures(ds))


def test_markers_become_missing_and_windows_can_be_dropped():
    ds = cicids_like()
    plan = {t.name: t for t in treatments_for(ds)}
    assert {"no_tcp_window", "neutralize_missing_markers", "missingness_only", "all_controls"} <= set(plan)
    assert "no_context_counts" not in plan
    rows = np.arange(len(ds.X))
    indicators = missingness_frame(ds)
    neutral = treated_features(ds, plan["neutralize_missing_markers"], rows, indicators)
    assert neutral["Init_Win_bytes_forward"].isna().sum() == 2
    assert ds.X["Init_Win_bytes_forward"].min() == -1  # The dataset itself is unchanged.
    dropped = treated_features(ds, plan["no_tcp_window"], rows, indicators)
    assert not {"Init_Win_bytes_forward", "Init_Win_bytes_backward"} & set(dropped.columns)
    assert treated_features(ds, plan["missingness_only"], rows, indicators).columns.tolist() == [
        "Init_Win_bytes_forward_marker", "Init_Win_bytes_backward_marker", "Flow Bytes/s_missing",
    ]


def test_unsw_marker_removes_the_service_column():
    X = pd.DataFrame(
        {"sttl": [1.0, 2.0, 3.0], "swin": [0.0, 1.0, 1.0], "ct_srv_src": [1.0, 2.0, 3.0],
         "service": ["-", "dns", "-"], "proto": ["tcp", "udp", "tcp"]}
    )
    ds = Dataset("unsw_nb15", X, np.array(["benign", "dos", "benign"], dtype=object), ("service", "proto"))
    plan = {t.name: t for t in treatments_for(ds)}
    assert plan["neutralize_missing_markers"].drop == ("service",)
    assert plan["no_context_counts"].drop == ("ct_srv_src",)
    assert plan["all_controls"].drop == ("swin", "service")
    assert missingness_frame(ds).iloc[:, 0].tolist() == [1.0, 0.0, 1.0]


def test_raw_rows_restore_repeats_and_flag_conflicts():
    X = pd.DataFrame({"a": [1.0, 1.0, 1.0, 2.0, 2.0, 3.0]})
    raw = Dataset("d", X, np.array(["dos", "dos", "benign", "dos", "dos", "benign"], dtype=object))
    rows = build_raw_rows(raw)
    table = pd.DataFrame({"v": rows.X["a"], "f": rows.family, "n": rows.count, "c": rows.conflicting})
    assert table.sort_values(["v", "f"]).values.tolist() == [
        [1.0, "benign", 1, True], [1.0, "dos", 2, True], [2.0, "dos", 2, False], [3.0, "benign", 1, False],
    ]


def test_raw_evaluation_weights_by_count():
    X = pd.DataFrame({"a": [1.0, 2.0, 3.0, 4.0]})
    rows = build_raw_rows(Dataset("d", X, np.array(["dos", "dos", "benign", "benign"], dtype=object)))
    rows.count = np.array([9, 1, 3, 1])
    model = RandomForestBaseline(RandomForestConfig(), 0)
    model.val_benign_scores = np.zeros(1000)
    attack, benign = np.array([1, 1, 0, 0], bool), np.array([0, 0, 1, 1], bool)
    result = evaluate_raw(model, rows, 0.01, np.array([-1.0, 1.0]), np.array([1.0, -1.0]), attack, benign)
    assert result["raw_recall"] == pytest.approx(0.1)  # One of ten attack rows.
    assert result["raw_distinct_recall"] == pytest.approx(0.5)
    assert result["raw_fpr"] == pytest.approx(0.75)  # Three of four benign rows.
    assert result["raw_attack_rows"] == 10


def small_config(seeds=(0,)) -> BaselineConfig:
    return BaselineConfig(
        datasets=(DatasetConfig(kind="synthetic", name="synthetic_a", seed=3),),
        seeds=seeds, max_train_per_family=2000, min_family_count=100, bootstrap_samples=100,
        rf=RandomForestConfig(n_estimators=10, max_depth=6, n_jobs=1),
    )


def test_run_writes_only_to_its_folder_and_resumes(tmp_path):
    other = tmp_path / "config_a"
    other.mkdir()
    (other / "results.csv").write_text("kept", encoding="utf-8")
    out = tmp_path / "artifacts"
    results = run(small_config(), out, log=lambda message: None)
    assert (other / "results.csv").read_text(encoding="utf-8") == "kept"
    assert set(results["treatment"]) == {REFERENCE, "remove_matching_signatures", "all_controls"}
    reference = results[results["treatment"] == REFERENCE]
    assert reference["raw_recall"].notna().all()
    assert results[results["treatment"] != REFERENCE]["raw_recall"].isna().all()

    lines = []
    again = run(small_config(), out, log=lines.append)
    assert not [line for line in lines if line.startswith("[")]  # Every fold was already done.
    pd.testing.assert_frame_equal(results, again)
    assert json.loads((out / "manifest.json").read_text(encoding="utf-8"))["identity"]["extra"]["experiment"] == "artifact_resistance"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_notebook_embeds_the_current_source():
    # If this fails, run: .venv/bin/python notebooks/build_artifact_notebook.py
    builder = _load("build_notebook", ROOT / "notebooks" / "build_notebook.py")
    assert f"SOURCE_VERSION = '{builder.source_hash()}'" in json.loads(json.dumps(NOTEBOOK.read_text(encoding="utf-8")))


def test_notebook_uses_a_new_folder_and_runs_on_small_csv_files(tmp_path, monkeypatch):
    builder = _load("build_artifact_notebook", ROOT / "notebooks" / "build_artifact_notebook.py")
    assert "results/config_a_artifacts" in builder.SETTINGS
    assert "aegis/results/config_a'" not in builder.SETTINGS
    fixtures = _load("test_notebook_fixtures", ROOT / "tests" / "test_notebook.py")
    rng = np.random.default_rng(0)
    fixtures.cicids_fixture(tmp_path / "data" / "CIC" / "MachineLearningCVE", rng)
    fixtures.unsw_fixture(tmp_path / "data" / "UNSW", rng)
    output = tmp_path / "results" / "config_a_artifacts"
    monkeypatch.setenv("AEGIS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(output))
    monkeypatch.setenv("AEGIS_SEEDS", "0,1")

    notebook = nbformat.read(NOTEBOOK, as_version=4)
    assert all(not cell.get("outputs") for cell in notebook.cells if cell.cell_type == "code")
    NotebookClient(
        notebook, timeout=900, kernel_name="python3", resources={"metadata": {"path": str(tmp_path)}}
    ).execute()
    text = "\n".join(
        str(out.get("text", "")) for cell in notebook.cells if cell.cell_type == "code" for out in cell.outputs
    )
    assert "Pipeline check passed" in text
    assert "No Config A results found" in text
    assert "Shortcut-dependent results" in text
    with zipfile.ZipFile(output / "aegis_artifact_results.zip") as bundle:
        assert set(bundle.namelist()) == {"manifest.json", "results.csv", "treatment_effects.csv"}
    results = pd.read_csv(output / "results.csv")
    assert {"neutralize_missing_markers", "missingness_only"} <= set(results["treatment"])
    assert set(results["seed"]) == {0, 1}


def test_notebook_comparison_reads_earlier_results_without_changing_them(tmp_path, capsys):
    builder = _load("build_artifact_notebook", ROOT / "notebooks" / "build_artifact_notebook.py")
    previous, output = tmp_path / "config_a", tmp_path / "config_a_artifacts"
    previous.mkdir()
    output.mkdir()
    data = {"identity": {"data": {"source_sha256": {"d": {"f.csv": "abc"}}}}}
    (previous / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    pd.DataFrame(
        {"dataset": ["d", "d"], "eval_family": ["dos", "dos"], "seed": [0, 0], "target_fpr": [0.01, 0.01],
         "scorer": ["rf", "fused"], "fold": ["holdout:dos", "holdout:dos"], "recall": [0.5, 0.9]}
    ).to_csv(previous / "results.csv", index=False)
    before = (previous / "results.csv").read_bytes()
    results = pd.DataFrame(
        {"dataset": ["d"], "family": ["dos"], "seed": [0], "target_fpr": [0.01],
         "treatment": [REFERENCE], "recall": [0.6]}
    )
    exec(builder.COMPARE, {"os": __import__("os"), "PREVIOUS_DIR": str(previous), "OUTPUT_DIR": str(output), "results": results})
    text = capsys.readouterr().out
    assert "Same source data as Config A: True" in text
    assert "mean gap 0.1000, largest 0.1000, 1 pairs" in text  # Compared with rf, not fused.
    assert (previous / "results.csv").read_bytes() == before
