import numpy as np
import pandas as pd
import pytest

from aegis.data.dataset import BENIGN, Dataset, column_report, remove_duplicates
from aegis.data.loaders import load_cicids2017, load_unsw_nb15, locate_data, project_to_shared
from aegis.data.splits import (
    cap_per_family,
    eligible_families,
    holdout_fold,
    make_partition,
    seen_fold,
)


def families():
    return np.array([BENIGN] * 500 + ["dos"] * 200 + ["scan"] * 100 + ["rare"] * 5, dtype=object)


def test_remove_duplicates_drops_repeats_and_conflicting_labels():
    X = pd.DataFrame({"a": [1.0, 1.0, 2.0, 2.0, 3.0], "b": [0.0, 0.0, 5.0, 5.0, 9.0]})
    ds = Dataset("t", X, [BENIGN, BENIGN, BENIGN, "dos", "dos"])
    cleaned, stats = remove_duplicates(ds)
    assert cleaned.X["a"].tolist() == [1.0, 3.0]
    assert cleaned.family.tolist() == [BENIGN, "dos"]
    assert stats == {"rows_before": 5, "rows_conflicting_labels": 2, "rows_after": 2}


def test_partition_is_disjoint_complete_stratified_and_repeatable():
    family = families()
    part = make_partition(family, seed=3)
    combined = np.concatenate([part.train, part.val, part.test])
    assert len(combined) == len(family) == len(np.unique(combined))
    assert (family[part.test] == "dos").sum() == 40
    assert (family[part.val] == "scan").sum() == 20
    again = make_partition(family, seed=3)
    assert np.array_equal(part.test, again.test)
    assert not np.array_equal(part.test, make_partition(family, seed=4).test)


def test_holdout_removes_family_from_training_and_validation():
    family = families()
    part = make_partition(family, seed=0)
    fold = holdout_fold(part, family, "dos", cap=None, seed=0)
    assert "dos" not in family[fold.train]
    assert "dos" not in family[fold.val]
    assert set(family[fold.test]) == {BENIGN, "dos"}


def test_seen_and_holdout_folds_test_identical_rows_of_the_family():
    family = families()
    part = make_partition(family, seed=0)
    seen = seen_fold(part, family, cap=None, seed=0)
    held = holdout_fold(part, family, "dos", cap=None, seed=0)
    in_seen = seen.test[np.isin(family[seen.test], [BENIGN, "dos"])]
    assert np.array_equal(in_seen, held.test)


def test_cap_limits_large_families_only():
    family = families()
    capped = cap_per_family(np.arange(len(family)), family, cap=100, seed=0)
    assert (family[capped] == BENIGN).sum() == 100
    assert (family[capped] == "rare").sum() == 5


def test_eligible_families_excludes_benign_and_rare():
    assert eligible_families(families(), min_count=50) == ["dos", "scan"]


def write_cicids(directory, label="DoS Hulk"):
    columns = {
        " Destination Port": [80, 443],
        " Flow Duration": [2_000_000, 1_000_000],
        " Total Fwd Packets": [3, 4],
        " Total Backward Packets": [1, 2],
        "Total Length of Fwd Packets": [100, 200],
        " Total Length of Bwd Packets": [50, 60],
        " Fwd Packet Length Mean": [33.0, 50.0],
        " Bwd Packet Length Mean": [50.0, 30.0],
        "Flow Bytes/s": ["Infinity", "12.5"],
        " Fwd IAT Mean": [4000.0, 2000.0],
        " Bwd IAT Mean": [0.0, 1000.0],
        " Label": [label, "BENIGN"],
    }
    pd.DataFrame(columns).to_csv(directory / "day.csv", index=False)


def test_cicids_loader_normalizes_names_labels_and_infinities(tmp_path):
    write_cicids(tmp_path)
    ds = load_cicids2017(tmp_path, drop_columns=["Destination Port"])
    assert ds.family.tolist() == ["dos", BENIGN]
    assert "Destination Port" not in ds.X.columns
    assert "Flow Duration" in ds.X.columns
    assert np.isnan(ds.X["Flow Bytes/s"].iloc[0])
    assert ds.X["Flow Bytes/s"].iloc[1] == pytest.approx(12.5)


def test_cicids_loader_accepts_garbled_web_attack_label(tmp_path):
    pd.DataFrame({" Flow Duration": [1], " Label": ["Web Attack � Brute Force"]}).to_csv(
        tmp_path / "web.csv", index=False, encoding="latin-1", errors="replace"
    )
    assert load_cicids2017(tmp_path).family.tolist() == ["web_attack"]


def test_holding_out_dos_keeps_ddos_flows_out_of_training_and_validation(tmp_path):
    # Flow Duration marks each row's original label, because the family name no longer does.
    labels = {"BENIGN": 0, "DoS Hulk": 100_000, "DDoS": 200_000, "PortScan": 300_000}
    rows = [(start + i, label) for label, start in labels.items() for i in range(100)]
    pd.DataFrame(rows, columns=[" Flow Duration", " Label"]).to_csv(tmp_path / "day.csv", index=False)
    ds = load_cicids2017(tmp_path)
    assert set(ds.family) == {BENIGN, "dos", "portscan"}

    duration = ds.X["Flow Duration"].to_numpy()
    is_ddos = (duration >= 200_000) & (duration < 300_000)
    is_hulk = (duration >= 100_000) & (duration < 200_000)
    assert is_ddos.sum() == is_hulk.sum() == 100

    partition = make_partition(ds.family, seed=0)
    fold = holdout_fold(partition, ds.family, "dos", None, seed=0)
    assert not is_ddos[fold.train].any() and not is_ddos[fold.val].any()
    assert not is_hulk[fold.train].any() and not is_hulk[fold.val].any()
    # Both remain in the test rows, where the held-out family is measured.
    assert is_ddos[fold.test].any() and is_hulk[fold.test].any()
    assert is_ddos[partition.train].any()  # The seen model does train on them.


def test_cicids_loader_rejects_unknown_label(tmp_path):
    write_cicids(tmp_path, label="Mystery")
    with pytest.raises(ValueError, match="Unknown CICIDS2017 label"):
        load_cicids2017(tmp_path)


def write_unsw(directory, attack="Backdoors", label=1):
    frame = pd.DataFrame(
        {
            "id": [1, 2],
            "dur": [2.0, 1.0],
            "proto": ["tcp", "udp"],
            "service": ["-", "dns"],
            "state": ["FIN", "CON"],
            "spkts": [3, 4],
            "dpkts": [1, 2],
            "sbytes": [100, 200],
            "dbytes": [50, 60],
            "smean": [33, 50],
            "dmean": [50, 30],
            "sinpkt": [4.0, 2.0],
            "dinpkt": [0.0, 1.0],
            "attack_cat": [attack, "Normal"],
            "label": [label, 0],
        }
    )
    frame.to_csv(directory / "UNSW_NB15_training-set.csv", index=False)


def test_unsw_loader_maps_families_and_keeps_categoricals(tmp_path):
    write_unsw(tmp_path)
    ds = load_unsw_nb15(tmp_path)
    assert ds.family.tolist() == ["backdoor", BENIGN]
    assert ds.categorical == ("proto", "service", "state")
    assert "id" not in ds.X.columns
    assert "label" not in ds.X.columns and "attack_cat" not in ds.X.columns


def test_unsw_loader_rejects_disagreeing_labels(tmp_path):
    write_unsw(tmp_path, label=0)
    with pytest.raises(ValueError, match="disagree"):
        load_unsw_nb15(tmp_path)


def test_locate_data_prefers_machine_learning_folder_and_checks_completeness(tmp_path):
    good = tmp_path / "CIC" / "MachineLearningCVE"
    other = tmp_path / "CIC" / "TrafficLabelling"
    unsw = tmp_path / "unsw"
    for folder in (good, other, unsw):
        folder.mkdir(parents=True)
    for i in range(8):
        (good / f"day{i}.pcap_ISCX.csv").touch()
        (other / f"day{i}.pcap_ISCX.csv").touch()
    (unsw / "UNSW_NB15_training-set.csv").touch()

    with pytest.raises(ValueError, match="testing-set"):
        locate_data(tmp_path)
    (unsw / "UNSW_NB15_testing-set.csv").touch()
    assert locate_data(tmp_path) == {"cicids2017": good, "unsw_nb15": unsw}

    (good / "day0.pcap_ISCX.csv").unlink()
    with pytest.raises(ValueError, match="expected 8"):
        locate_data(tmp_path)


def test_locate_data_finds_nothing_in_an_empty_folder(tmp_path):
    assert locate_data(tmp_path) == {}


def test_column_report_flags_problems():
    X = pd.DataFrame({"a": [1.0, np.nan, -1.0, 2.0], "b": [5.0] * 4, "p": ["x", "y", "x", "x"]})
    report = column_report(Dataset("t", X, [BENIGN] * 4, ("p",))).set_index("column")
    assert report.loc["a", "missing_share"] == 0.25
    assert report.loc["a", "negative_share"] == 0.25
    assert bool(report.loc["b", "constant"]) is True
    assert bool(report.loc["p", "constant"]) is False


def test_shared_features_align_columns_and_units(tmp_path):
    cic_dir, unsw_dir = tmp_path / "cic", tmp_path / "unsw"
    cic_dir.mkdir()
    unsw_dir.mkdir()
    write_cicids(cic_dir)
    write_unsw(unsw_dir)
    cic = project_to_shared(load_cicids2017(cic_dir))
    unsw = project_to_shared(load_unsw_nb15(unsw_dir))
    assert list(cic.X.columns) == list(unsw.X.columns)
    assert cic.categorical == unsw.categorical == ()
    assert cic.X["duration_s"].iloc[0] == pytest.approx(2.0)
    assert unsw.X["duration_s"].iloc[0] == pytest.approx(2.0)
    assert cic.X["src_interarrival_ms"].iloc[0] == pytest.approx(4.0)
    assert unsw.X["src_interarrival_ms"].iloc[0] == pytest.approx(4.0)
