import importlib.util
import json
import re
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
    signature_columns,
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
                 "raw_recall": raw, "overlap_excluded_recall": raw, "recall": 0.5, "auc": 0.9, "attack_rows_hash": "a",
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
    assert effects.loc["no_tcp_window", "overlap_shortcut_dependent"]
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


def test_overlap_marks_vectors_with_several_attack_families_and_keeps_them_in_raw_recall():
    X = pd.DataFrame({"a": [1.0, 1.0, 1.0, 2.0, 2.0, 3.0, 4.0]})
    family = np.array(["dos", "exploits", "benign", "dos", "benign", "dos", "benign"], dtype=object)
    rows = build_raw_rows(Dataset("d", X, family))
    table = pd.DataFrame({"v": rows.X["a"], "f": rows.family, "o": rows.attack_overlap}).sort_values(["v", "f"])
    # Vector 1 carries dos and exploits, so all its entries are marked, benign included. Vector 2 is attack
    # and benign only, which is not an attack-label overlap.
    assert table["o"].tolist() == [True, True, True, False, False, False, False]

    model = RandomForestBaseline(RandomForestConfig(), 0)
    model.val_benign_scores = np.zeros(1000)
    attack = rows.family.astype(str) == "dos"
    benign = rows.family.astype(str) == "benign"
    scores = np.where(rows.X["a"].to_numpy() == 1.0, -1.0, 1.0)  # Only the overlapping vector is missed.
    result = evaluate_raw(model, rows, 0.01, scores[attack], -np.ones(benign.sum()), attack, benign)
    assert result["raw_recall"] == pytest.approx(2 / 3)
    assert result["overlap_excluded_recall"] == pytest.approx(1.0)
    assert result["raw_attack_overlap_share"] == pytest.approx(1 / 3)
    assert result["overlap_excluded_attack_rows"] == 2
    assert result["overlap_excluded_benign_rows_removed"] == 1


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


# Feature columns of the original CICIDS2017 release as loaded (Destination Port and Fwd Header Length.1 dropped).
ORIGINAL_COLUMNS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
    "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]
UNSW_COLUMNS = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl", "sload",
    "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt",
    "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]
# Feature columns of the improved release (CNS 2022 labelling code), after identifiers and Dst Port are dropped.
IMPROVED_COLUMNS = [
    "Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
    "Total Length of Bwd Packet", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
    "Bwd URG Flags", "Fwd RST Flags", "Bwd RST Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s",
    "Bwd Packets/s", "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "FWD Init Win Bytes", "Bwd Init Win Bytes",
    "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min", "ICMP Code", "ICMP Type", "Total TCP Flow Time",
]
IMPROVED_WINDOW = ("FWD Init Win Bytes", "Bwd Init Win Bytes")


def frame_with(columns, rows=4, marker_columns=(), marker=-1.0):
    X = pd.DataFrame(np.arange(1, rows * len(columns) + 1, dtype=np.float32).reshape(rows, len(columns)),
                     columns=columns)
    for column in marker_columns:
        X.loc[0, column] = marker
    return X


def improved_like(columns=IMPROVED_COLUMNS) -> Dataset:
    # The improved release writes an unobserved window as 0 (format check, 2026-11-08).
    X = frame_with(columns, marker_columns=[c for c in IMPROVED_WINDOW if c in columns], marker=0.0)
    return Dataset("cicids2017_improved", X, np.array(["benign", "dos", "portscan", "benign"], dtype=object))


def add_improved_windows(folder: Path, rng: np.random.Generator) -> None:
    """Give the improved-format notebook fixture the TCP window columns the real release has."""
    for path in sorted(folder.glob("*day.csv")):
        frame = pd.read_csv(path)
        for column in IMPROVED_WINDOW:
            frame[column] = rng.choice([0, 229, 8192, 65535], len(frame))
        frame.to_csv(path, index=False)


def test_original_release_treatments_and_signatures_are_unchanged():
    # Written out from the plan the measured audit used, so any change to it fails here.
    ds = Dataset("cicids2017", frame_with(ORIGINAL_COLUMNS, marker_columns=["Init_Win_bytes_forward"]),
                 np.array(["benign", "dos", "portscan", "benign"], dtype=object))
    window = ("Init_Win_bytes_forward", "Init_Win_bytes_backward")
    assert treatments_for(ds, has_suspect_benign=True) == [
        Treatment(REFERENCE),
        Treatment("remove_matching_signatures", remove_signatures=True),
        Treatment("no_tcp_window", drop=window),
        Treatment("neutralize_missing_markers", neutralize=window),
        Treatment("missingness_only", missingness_only=True),
        Treatment("exclude_suspect_benign", exclude_suspect=True),
        Treatment("all_controls", drop=window, remove_signatures=True),
    ]
    old_timing = re.compile(r"Duration|IAT|/s|Active|Idle|Bulk Rate")
    assert signature_columns(ds) == [c for c in ORIGINAL_COLUMNS if not old_timing.search(c)]
    assert missingness_frame(ds).columns.tolist() == ["Init_Win_bytes_forward_marker", "Init_Win_bytes_backward_marker"]


def test_unsw_treatments_and_signatures_are_unchanged():
    X = frame_with(UNSW_COLUMNS).astype(object)
    X["proto"], X["state"], X["service"] = "tcp", "FIN", ["-", "dns", "http", "-"]
    ds = Dataset("unsw_nb15", X, np.array(["benign", "dos", "exploits", "benign"], dtype=object),
                 ("proto", "service", "state"))
    context = tuple(c for c in UNSW_COLUMNS if c.startswith("ct_"))
    assert treatments_for(ds) == [
        Treatment(REFERENCE),
        Treatment("remove_matching_signatures", remove_signatures=True),
        Treatment("no_tcp_window", drop=("swin", "dwin")),
        Treatment("neutralize_missing_markers", drop=("service",)),
        Treatment("missingness_only", missingness_only=True),
        Treatment("no_context_counts", drop=context),
        Treatment("service_marker_only", marker_only=("service",)),
        Treatment("all_controls", drop=("swin", "dwin", "service"), remove_signatures=True),
    ]
    excluded = {"dur", "rate", "sload", "dload", "sinpkt", "dinpkt", "sjit", "djit", "tcprtt", "synack", "ackdat",
                "stcpb", "dtcpb"}
    assert signature_columns(ds) == [c for c in UNSW_COLUMNS if c not in excluded]


def test_improved_release_uses_its_own_column_names():
    ds = improved_like()
    plan = {t.name: t for t in treatments_for(ds)}
    assert list(plan) == [REFERENCE, "remove_matching_signatures", "no_tcp_window", "neutralize_missing_markers",
                          "missingness_only", "all_controls"]
    assert plan["no_tcp_window"].drop == IMPROVED_WINDOW
    assert plan["neutralize_missing_markers"].neutralize == IMPROVED_WINDOW
    assert plan["neutralize_missing_markers"].marker == 0
    assert plan["all_controls"].drop == IMPROVED_WINDOW and plan["all_controls"].remove_signatures
    assert missingness_frame(ds).columns.tolist() == [f"{c}_marker" for c in IMPROVED_WINDOW]
    neutral = treated_features(ds, plan["neutralize_missing_markers"], np.arange(4), missingness_frame(ds))
    assert neutral[list(IMPROVED_WINDOW)].isna().sum().tolist() == [1, 1]


def test_improved_signatures_leave_out_timing_only():
    kept = set(signature_columns(improved_like()))
    timing = {"Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Fwd IAT Mean", "Bwd IAT Total", "Fwd Packets/s",
              "Active Mean", "Idle Max", "Fwd Bulk Rate Avg", "Bwd Bulk Rate Avg", "Total TCP Flow Time"}
    assert not timing & kept
    assert {"Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Act Data Pkts", "Total Fwd Packet",
            *IMPROVED_WINDOW, "ICMP Type"} <= kept
    assert len(IMPROVED_COLUMNS) - len(kept) == 30  # Duration 1, rates 4, IAT 14, bulk rates 2, active/idle 8, TCP time 1.


@pytest.mark.parametrize("missing", IMPROVED_WINDOW)
def test_improved_release_refuses_an_absent_window_column(missing):
    ds = improved_like([c for c in IMPROVED_COLUMNS if c != missing])
    with pytest.raises(ValueError, match=missing):
        treatments_for(ds)
    with pytest.raises(ValueError, match=missing):
        missingness_frame(ds)


def test_improved_release_with_original_names_is_refused():
    columns = [c for c in IMPROVED_COLUMNS if c not in IMPROVED_WINDOW] + ["Init_Win_bytes_forward",
                                                                        "Init_Win_bytes_backward"]
    with pytest.raises(ValueError, match="FWD Init Win Bytes"):
        treatments_for(improved_like(columns))


def test_improved_release_without_timing_columns_is_refused():
    columns = [c for c in IMPROVED_COLUMNS if not re.search(r"Duration|IAT|/s|Active|Idle|Bulk Rate|Flow Time", c)]
    with pytest.raises(ValueError, match="timing"):
        signature_columns(improved_like(columns))


def test_unknown_real_dataset_has_no_profile():
    with pytest.raises(ValueError, match="profile"):
        treatments_for(Dataset("cse_cic_ids2018", frame_with(["a"]), np.array(["benign"] * 4, dtype=object)))


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
    assert results["overlap_excluded_recall"].notna().all()

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


def test_saved_scores_reproduce_the_reported_recall(tmp_path):
    out = tmp_path / "scored"
    results = run(small_config(), out, log=lambda message: None, save_scores=True)
    row = results[(results["treatment"] == REFERENCE) & (results["target_fpr"] == 0.01)].iloc[0]
    saved = np.load(out / "scores" / f"synthetic_a_seed0_reference__{row['family']}.npz")
    threshold = saved["thresholds"][list(saved["target_fprs"]).index(0.01)]
    attack, count = saved["raw_is_attack"], saved["raw_count"]
    caught = saved["raw_score"] > threshold
    assert count[attack & caught].sum() / count[attack].sum() == pytest.approx(row["raw_recall"])
    assert (saved["test_score"][saved["test_is_attack"]] > threshold).mean() == pytest.approx(row["recall"])
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["identity"]["extra"]["per_row_scores"] is True


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
    add_improved_windows(tmp_path / "data" / "CIC" / "MachineLearningCVE", rng)
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
    improved = set(results.loc[results["dataset"] == "cicids2017_improved", "treatment"])
    assert {"no_tcp_window", "neutralize_missing_markers"} <= improved
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
