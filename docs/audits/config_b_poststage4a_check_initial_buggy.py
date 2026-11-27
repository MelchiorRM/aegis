"""Read-only post-stage-4a integrity checks: ledger, artifacts, preservation. No performance metric is read or compared."""
import csv, hashlib, json, sys
from pathlib import Path

import pandas as pd

from aegis.config_b import identity, protocol
from aegis.config_b.compute import Ledger
from aegis.frozen import frozen_digest

OUT = Path("results/config_b")
PRE_HASHES, PRE_LEDGER = Path(sys.argv[1]), Path(sys.argv[2])
FAMS = protocol.HELD_OUT_FAMILIES
TREATMENTS = (*protocol.RULE_TREATMENTS, *protocol.OUTSIDE_RULE)
ok = True


def check(cond, msg):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + msg)


# --- 1. Ledger ---
ledger = Ledger(OUT / "compute_ledger.csv", 71.5)
pre = list(csv.DictReader(PRE_LEDGER.open()))
now = list(csv.DictReader((OUT / "compute_ledger.csv").open()))
check(now[:len(pre)] == pre, f"[1] ledger: the {len(pre)} rows before stage 4a are unchanged; {len(now) - len(pre)} rows appended")
rows = [r for r in ledger.rows if r["stage"] == "4a"]
check(all(r["stage"] == "4a" for r in ledger.rows[len(pre):]), "[1] every appended row is stage 4a")
fits = [r for r in rows if r["label"].startswith("B:") and r["label"].split(":")[1] in TREATMENTS]
other = [r for r in rows if r not in fits]
by_t = {t: sum(1 for r in fits if r["label"].split(":")[1] == t) for t in TREATMENTS}
check(len(fits) == 100 and set(by_t.values()) == {20}, f"[1] {len(fits)} fit rows, all arm B, by treatment {by_t}")
check(len({r["label"] for r in fits}) == len(fits), "[1] no fit was recorded twice")
for r in other:
    print(f"     non-fit row: {r['label']}: {r['cpu_seconds']:.1f} s CPU")
total = ledger.measured_hours("4a")
cpu_fit = sum(r["cpu_seconds"] for r in fits) / 3600
print(f"[1] stage 4a: fits {cpu_fit:.4f} CPU-h by treatment "
      f"{ {t: round(sum(r['cpu_seconds'] for r in fits if r['label'].split(':')[1] == t) / 3600, 4) for t in TREATMENTS} }; "
      f"outside fits {total - cpu_fit:.4f}; total {total:.4f} of ceiling {protocol.STAGE_CEILINGS['4a']}")
done = [s for s in protocol.STAGES if (OUT / f"stage_{s}.done").exists()]
check(done == ["1", "2a", "2b", "3", "4a"], f"[1] finished stages {done}")
p = ledger.projection("4b", done)
print(f"[1] spent {ledger.total_hours():.4f} CPU-h (bank included); remaining approved budget {71.5 - ledger.total_hours():.3f}; "
      f"ratio {p['ratio_measured_to_ceiling']:.4f}; remaining estimates { {k: round(v, 3) for k, v in p['remaining_estimates'].items()} }; "
      f"projected total {p['projected_total']:.2f}")
check(ledger.total_hours() < protocol.IN_STAGE_STOP and p["projected_total"] <= 71.5, "[1] below the in-stage stop and within the approved budget")
s = json.loads((OUT / "stage_4a.done").read_text())
print(f"[1] stage_4a.done (pre-stage projection, issue 33): stage 4a {s['measured_by_stage']['4a']:.4f}; ratio {s['ratio_measured_to_ceiling']:.4f}; "
      f"total {s['measured_total']:.4f}; projected {s['projected_total']:.2f}")
check(all(abs(s["measured_by_stage"][k] - ledger.measured_hours(k)) < 1e-9 for k in ("0", "1", "2a", "2b", "3")),
      "[1] stage_4a.done's figures for the bank and stages 1 to 3 equal the ledger")
load = [r for r in rows if r["label"].startswith("load")]
check(load and abs(s["measured_by_stage"]["4a"] - sum(r["cpu_seconds"] for r in load) / 3600) < 1e-9,
      "[1] stage_4a.done's own-stage figure is the dataset load only (issue 33)")
times = [r["finished_utc"] for r in ledger.rows[len(pre):]]
print(f"[1] stage 4a finished_utc from {times[0]} to {times[-1]}; out-of-order rows: {sum(b < a for a, b in zip(times, times[1:]))}")

# --- 2. Artifacts ---
sel = pd.read_csv(OUT / "selections_B.csv", dtype={"selected": str})
missing, bad, rowset = [], [], []
for seed in protocol.FOLD_SEEDS:
    for held in FAMS:
        ref = pd.read_csv(OUT / "folds" / f"cicids2017_improved__seed{seed}__B_reference_holdout_{held}.csv")
        want = float(sel[(sel.seed == seed) & (sel.outer_family == held)].selected.iloc[0])
        for t in TREATMENTS:
            fpath = OUT / "folds" / f"cicids2017_improved__seed{seed}__B_{t}_holdout_{held}.csv"
            apath = OUT / "accounting" / f"folds__seed{seed}__B__{t}__holdout__{held}.json"
            if not fpath.exists() or not apath.exists():
                missing.append((seed, held, t, fpath.exists(), apath.exists()))
                continue
            df, acc = pd.read_csv(fpath), json.loads(apath.read_text())
            problems = []
            if not ((df.arm == "B").all() and (df.seed == seed).all() and (df.treatment == t).all() and (df.fold == "holdout").all()):
                problems.append("arm/seed/treatment/fold")
            if not (df.ratio == want).all() or float(acc["ratio"]) != want:
                problems.append(f"ratio {sorted(set(df.ratio))}/{acc['ratio']} != {want}")
            if list(df.family.unique()) != [held] or len(df) != 2:
                problems.append("family rows")
            if not (df.replay_total == acc["replay_total"]).all():
                problems.append("replay total vs accounting")
            if held in acc.get("realized", {}) or held in acc.get("families", {}):
                problems.append("held-out family replayed")
            if acc["arm"] != "B" or acc["seed"] != seed or acc["label"] != f"B:{t}:holdout:{held}":
                problems.append("accounting arm/seed/label")
            if problems:
                bad.append((seed, held, t, problems))
            # Same evaluation rows as the stage 3 reference fold (row hashes only; no metric is read).
            rowset.append(set(df.attack_rows_hash) == set(ref.attack_rows_hash) and set(df.benign_rows_hash) == set(ref.benign_rows_hash))
check(not missing, f"[2] all 100 audit fold CSVs and 100 accounting files present (5 seeds x 4 held-out families x 5 treatments); missing {missing}")
check(not bad, f"[2] every audit fold: arm B, seed, treatment, held-out fold, B's selected ratio for that seed and family, "
               f"2 rows of the held-out family, replay total = accounting, held-out family never replayed; problems {bad}")
print(f"[2] info: {sum(rowset)} of {len(rowset)} audit folds evaluate the same attack/benign row sets as the stage 3 B reference fold (row hashes)")
expected = {f"cicids2017_improved__seed{s}__{a}_reference_{f}.csv" for a in protocol.ARMS for s in protocol.FOLD_SEEDS
            for f in ("seen", *[f"holdout_{x}" for x in FAMS])}
expected |= {f"cicids2017_improved__seed{s}__B_{t}_holdout_{h}.csv" for s in protocol.FOLD_SEEDS for h in FAMS for t in TREATMENTS}
present = {p.name for p in (OUT / "folds").glob("*.csv")}
check(present == expected and not any((OUT / "determinism").iterdir()),
      f"[2] folds/ holds exactly the 75 reference + 100 audit files ({len(present)}); unexpected {sorted(present - expected)}; determinism/ still empty")
fp = json.loads((OUT / "preprocessing_fingerprints.json").read_text())
want_keys = {f"seed{s}:holdout:{h}:{t}" for s in protocol.FOLD_SEEDS for h in FAMS for t in TREATMENTS}
check(want_keys <= set(fp), f"[2] preprocessing fingerprints registered for all {len(want_keys)} audit folds ({len(fp)} keys in all)")

# --- 3. Preservation of what existed after stage 3 ---
changed, gone, lines = [], [], PRE_HASHES.read_text().splitlines()
for line in lines:
    digest, name = line.split(maxsplit=1)
    path = OUT / name
    if not path.exists():
        gone.append(name)
    elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        changed.append(name)
print(f"[3] of {len(lines)} files hashed after stage 3: changed {changed}, removed {gone}")
check(not gone and set(changed) <= {"./preprocessing_fingerprints.json", "./compute_ledger.csv"},
      "[3] no stage 3 or earlier output changed or removed, except the ledger (append-only, checked in [1]) and the fingerprint registry")
old_fp = json.loads(Path(sys.argv[3]).read_text())
check(all(fp.get(k) == v for k, v in old_fp.items()), f"[3] all {len(old_fp)} fingerprints registered before stage 4a are unchanged")

# --- 4. Identities ---
check(frozen_digest() == "25685b84dd83f65c", f"[4] Config A identity {frozen_digest()}")
check(identity.digest() == "7b900fea59b6cf35", f"[4] Config B identity {identity.digest()} equals the signed addendum")
print("POST-STAGE-4A CHECKS: " + ("ALL PASSED" if ok else "FAILURES ABOVE"))
