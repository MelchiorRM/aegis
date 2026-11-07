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
    meets_shortcut_rule,
    missingness_frame,
    rule_report,
    run,
    signatures,
    summarize_treatments,
    training_rows,
    treated_features,
    treatments_for,
    without_suspect_benign,
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
    flagged = treated_features(ds, plan["service_marker_only"], np.arange(3), missingness_frame(ds))
    assert "service" not in flagged and flagged["service_marker"].tolist() == [1.0, 0.0, 1.0]


def test_shortcut_rule_needs_the_drop_and_an_interval_on_the_side_of_a_decrease():
    assert meets_shortcut_rule(0.10, 0.01)
    assert not meets_shortcut_rule(0.09, 0.05)  # Too small.
    assert not meets_shortcut_rule(0.30, 0.0)  # The interval reaches zero.
    assert not meets_shortcut_rule(-0.30, -0.40)  # Recall rose, however clearly.
    assert not meets_shortcut_rule(float("nan"), float("nan"))


def effect_rows(treatment, reference, treated, benign_hash="b", family="f"):
    rows = []
    for seed, (before, after) in enumerate(zip(reference, treated)):
        for name, raw in ((REFERENCE, before), (treatment, after)):
            rows.append(
                {"dataset": "d", "family": family, "target_fpr": 0.01, "seed": seed, "treatment": name,
                 "raw_recall": raw, "recall": 0.5, "auc": 0.9, "attack_rows_hash": "a",
                 "benign_rows_hash": benign_hash if name == treatment else "b"}
            )
    return pd.DataFrame(rows)


def test_rule_uses_raw_recall_and_reports_every_comparison():
    drop = effect_rows("no_tcp_window", [0.8, 0.82, 0.79], [0.5, 0.52, 0.51])
    floor = effect_rows("all_controls", [0.02, 0.01, 0.03], [0.0, 0.0, 0.0], family="g")
    gain = effect_rows("no_context_counts", [0.4, 0.4, 0.4], [0.9, 0.95, 0.92])
    probe = effect_rows("missingness_only", [0.8, 0.8, 0.8], [0.0, 0.0, 0.0])
    results = pd.concat([drop, floor, gain[gain.treatment != REFERENCE], probe[probe.treatment != REFERENCE]])
    effects = summarize_treatments(results, 100, 0.01).set_index("treatment")
    assert effects.loc["no_tcp_window", "shortcut_dependent"]
    assert not effects.loc["no_tcp_window", "dedup_shortcut_dependent"]  # Deduplicated recall did not move.
    assert not effects.loc["no_context_counts", "shortcut_dependent"]
    assert not effects.loc["missingness_only", "shortcut_dependent"]  # A probe, outside the rule.
    report = rule_report(effects.reset_index(), 0.01)
    assert report["n_comparisons"] == 3 and report["n_shortcut_dependent"] == 1
    assert report["n_not_testable"] == 1 and not effects.loc["all_controls", "rule_testable"]
    assert report["treatments_outside_the_rule"] == ["missingness_only"]
    assert "not an unbiased" in report["evaluation_role"]


def test_rule_applies_only_at_the_primary_fpr():
    results = effect_rows("no_tcp_window", [0.8, 0.82, 0.79], [0.5, 0.52, 0.51])
    effects = summarize_treatments(results, 100, primary_fpr=0.001)
    assert not effects["shortcut_dependent"].any()
    assert rule_report(effects, 0.001)["n_comparisons"] == 0


def test_comparison_on_different_rows_is_refused():
    results = effect_rows("no_tcp_window", [0.8, 0.8], [0.5, 0.5], benign_hash="other")
    with pytest.raises(ValueError, match="not evaluated on the reference rows"):
        summarize_treatments(results, 100, 0.01)
    allowed = effect_rows("exclude_suspect_benign", [0.8, 0.8], [0.5, 0.5], benign_hash="other")
    assert summarize_treatments(allowed, 100, 0.01).loc[0, "role"] == "label_sensitivity"


def test_excluding_suspect_rows_leaves_attack_rows_alone():
    fold = Fold("holdout:web", np.array([0, 2, 3]), np.array([4]), np.array([1, 5]), "web")
    suspect = np.array([True, False, False, False, True, True])
    trimmed = without_suspect_benign(fold, suspect)
    assert trimmed.train.tolist() == [2, 3] and trimmed.val.tolist() == [] and trimmed.test.tolist() == [1]


def test_suspect_list_skips_other_data_and_refuses_a_mismatched_copy():
    from aegis.data import suspect_benign as module

    assert module.suspect_benign_mask(cicids_like()) is None  # The row count differs.
    columns = [*module._CHECK_COLUMNS]
    X = pd.DataFrame(np.zeros((module.CLEANED_ROWS, len(columns)), dtype=np.float32), columns=columns)
    family = np.full(module.CLEANED_ROWS, "benign", dtype=object)
    with pytest.raises(ValueError, match="do not match"):
        module.suspect_benign_mask(Dataset("cicids2017", X, family))


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
    assert results["raw_recall"].notna().all()  # The primary metric exists for every treatment.
    assert results.groupby(["seed", "family"])["attack_rows_hash"].nunique().eq(1).all()
    rule = json.loads((out / "shortcut_rule.json").read_text(encoding="utf-8"))
    assert rule["n_comparisons"] == reference["family"].nunique() * 2
    assert rule["primary_metric"] == "raw_recall"

    lines = []
    again = run(small_config(), out, log=lines.append)
    assert not [line for line in lines if line.startswith("[")]  # Every fold was already done.
    pd.testing.assert_frame_equal(results, again)
    assert json.loads((out / "manifest.json").read_text(encoding="utf-8"))["identity"]["extra"]["experiment"] == "artifact_resistance"


def test_label_sensitivity_excludes_rows_only_in_its_own_treatment(tmp_path, monkeypatch):
    def mark(ds):
        mask = np.zeros(len(ds.X), dtype=bool)
        mask[np.flatnonzero(ds.family.astype(str) == "benign")[:200]] = True
        return mask

    monkeypatch.setattr("aegis.experiments.artifacts.suspect_benign_mask", mark)
    out = tmp_path / "artifacts"
    results = run(small_config(), out, log=lambda message: None)
    effects = pd.read_csv(out / "treatment_effects.csv")
    assert effects.loc[effects["treatment"] == "exclude_suspect_benign", "role"].eq("label_sensitivity").all()
    rows = results.set_index(["treatment", "family", "target_fpr"]).sort_index()
    family = results["family"].iloc[0]
    baseline, excluded = rows.loc[(REFERENCE, family, 0.01)], rows.loc[("exclude_suspect_benign", family, 0.01)]
    assert excluded["n_benign"] < baseline["n_benign"]
    assert excluded["raw_benign_rows"] < baseline["raw_benign_rows"]
    assert excluded["n_attack"] == baseline["n_attack"] and excluded["raw_attack_rows"] == baseline["raw_attack_rows"]
    assert excluded["attack_rows_hash"] == baseline["attack_rows_hash"]
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["identity"]["extra"]["suspect_benign_excluded_in_sensitivity_only"]["synthetic_a"]["cleaned_rows"] == 200


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
        assert set(bundle.namelist()) == {"manifest.json", "results.csv", "treatment_effects.csv", "shortcut_rule.json"}
    results = pd.read_csv(output / "results.csv")
    assert {"neutralize_missing_markers", "missingness_only", "service_marker_only"} <= set(results["treatment"])
    assert "not an unbiased generalization estimate" in text
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
