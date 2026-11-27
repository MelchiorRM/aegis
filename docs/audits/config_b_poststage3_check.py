"""Read-only post-stage-3 integrity checks: ledger, artifacts, preservation. No performance metric is read or compared."""
import csv, hashlib, json, sys
from pathlib import Path

import pandas as pd

from aegis.config_b import identity, protocol
from aegis.config_b.compute import Ledger
from aegis.frozen import frozen_digest

OUT = Path("results/config_b")
PRE_HASHES, PRE_LEDGER = Path(sys.argv[1]), Path(sys.argv[2])
FAMS = protocol.HELD_OUT_FAMILIES
ok = True


def check(cond, msg):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + msg)


# --- 1. Ledger ---
ledger = Ledger(OUT / "compute_ledger.csv", 71.5)
pre = list(csv.DictReader(PRE_LEDGER.open()))
now = list(csv.DictReader((OUT / "compute_ledger.csv").open()))
check(now[:len(pre)] == pre, f"[1] ledger: the {len(pre)} rows before stage 3 are unchanged; {len(now) - len(pre)} rows appended")
rows3 = [r for r in ledger.rows if r["stage"] == "3"]
check(all(r["stage"] == "3" for r in ledger.rows[len(pre):]), "[1] every appended row is stage 3")
fits = [r for r in rows3 if ":reference:" in r["label"]]
other = [r for r in rows3 if r not in fits]
by_arm = {a: sum(1 for r in fits if r["label"].startswith(a + ":")) for a in protocol.ARMS}
cpu_fit = sum(r["cpu_seconds"] for r in fits) / 3600
check(len(fits) == 70 and by_arm == {"A": 20, "B": 25, "B0": 25}, f"[1] {len(fits)} fit rows, by arm {by_arm}")
for r in other:
    print(f"     non-fit row: {r['label']}: {r['cpu_seconds']:.1f} s CPU")
total3 = ledger.measured_hours("3")
print(f"[1] stage 3: fits {cpu_fit:.4f} CPU-h by arm "
      f"{ {a: round(sum(r['cpu_seconds'] for r in fits if r['label'].startswith(a + ':')) / 3600, 4) for a in protocol.ARMS} }; "
      f"outside fits {total3 - cpu_fit:.4f}; total {total3:.4f} of ceiling {protocol.STAGE_CEILINGS['3']}")
done = [s for s in protocol.STAGES if (OUT / f"stage_{s}.done").exists()]
p = ledger.projection("4a", done)
print(f"[1] spent {ledger.total_hours():.4f} CPU-h; remaining approved budget {71.5 - ledger.total_hours():.3f}; "
      f"ratio {p['ratio_measured_to_ceiling']:.4f}; remaining estimates { {k: round(v, 3) for k, v in p['remaining_estimates'].items()} }; "
      f"projected total {p['projected_total']:.2f}")
s = json.loads((OUT / "stage_3.done").read_text())
print(f"[1] stage_3.done (pre-stage projection, issue 33): stage 3 {s['measured_by_stage']['3']:.4f}; ratio {s['ratio_measured_to_ceiling']:.4f}; "
      f"total {s['measured_total']:.4f}; projected {s['projected_total']:.2f}")
check(all(abs(s["measured_by_stage"][k] - ledger.measured_hours(k)) < 1e-9 for k in ("1", "2a", "2b")),
      "[1] stage_3.done's figures for stages 1, 2a and 2b equal the ledger")
load = [r for r in rows3 if r["label"].startswith("load")]
check(load and abs(s["measured_by_stage"]["3"] - sum(r["cpu_seconds"] for r in load) / 3600) < 1e-9,
      "[1] stage_3.done's own-stage figure is the dataset load only (issue 33)")
times = [r["finished_utc"] for r in ledger.rows[len(pre):]]
print(f"[1] stage 3 finished_utc from {times[0]} to {times[-1]}; out-of-order rows: {sum(b < a for a, b in zip(times, times[1:]))}")

# --- 2. Artifacts ---
selected = {arm: pd.read_csv(OUT / f"selections_{arm}.csv", dtype={"selected": str}) for arm in ("B", "B0")}
missing, bad = [], []
for arm in protocol.ARMS:
    for seed in protocol.FOLD_SEEDS:
        for fold in ("seen", *[f"holdout_{f}" for f in FAMS]):
            held = None if fold == "seen" else fold[len("holdout_"):]
            fpath = OUT / "folds" / f"cicids2017_improved__seed{seed}__{arm}_reference_{fold}.csv"
            apath = OUT / "accounting" / f"folds__seed{seed}__{arm}__reference__{fold.replace('_', '__', 1) if held else 'seen'}.json"
            if not fpath.exists() or not apath.exists():
                missing.append((arm, seed, fold, fpath.exists(), apath.exists()))
                continue
            df, acc = pd.read_csv(fpath), json.loads(apath.read_text())
            if arm == "A":
                want = 0.0
            elif held is None:
                want = protocol.SEEN_FOLD_RATIO
            else:
                sel = selected[arm]
                want = float(sel[(sel.seed == seed) & (sel.outer_family == held)].selected.iloc[0])
            families = list(FAMS) if held is None else [held]
            problems = []
            if not ((df.arm == arm).all() and (df.seed == seed).all() and (df.treatment == "reference").all()):
                problems.append("arm/seed/treatment")
            if not (df.ratio == want).all() or float(acc["ratio"]) != want:
                problems.append(f"ratio {sorted(set(df.ratio))}/{acc['ratio']} != {want}")
            if sorted(df.family.unique()) != sorted(families) or len(df) != 2 * len(families):
                problems.append("family rows")
            if not (df.replay_total == acc["replay_total"]).all():
                problems.append("replay total vs accounting")
            if arm == "A" and acc["replay_total"] != 0:
                problems.append("arm A has replays")
            if held and (held in acc.get("realized", {}) or held in acc.get("families", {})):
                problems.append("held-out family replayed")
            if acc["arm"] != arm or acc["seed"] != seed:
                problems.append("accounting arm/seed")
            if problems:
                bad.append((arm, seed, fold, problems))
check(not missing, f"[2] all 75 fold CSVs and 75 accounting files present (3 arms x 5 seeds x 5 folds); missing {missing}")
check(not bad, f"[2] every fold: arm, seed, reference treatment, registered ratio (A 0; seen 0.25; held-out = selection), "
               f"expected family rows, replay total = accounting, A without replay, held-out family never replayed; problems {bad}")
extra = sorted({p.name for p in (OUT / "folds").glob("*.csv")} - {f"cicids2017_improved__seed{s}__{a}_reference_{f}.csv"
               for a in protocol.ARMS for s in protocol.FOLD_SEEDS for f in ("seen", *[f"holdout_{x}" for x in FAMS])})
check(not extra and not any((OUT / "determinism").iterdir()), f"[2] no unexpected fold files {extra}; determinism/ still empty")
fp = json.loads((OUT / "preprocessing_fingerprints.json").read_text())
want_keys = {f"seed{s}:{'seen' if f == 'seen' else 'holdout:' + f}:reference" for s in protocol.FOLD_SEEDS for f in ("seen", *FAMS)}
check(want_keys <= set(fp), f"[2] preprocessing fingerprints registered for all {len(want_keys)} outer folds (shared by A, B and B0)")

# --- 3. Preservation of what existed before stage 3 ---
changed, gone = [], []
for line in PRE_HASHES.read_text().splitlines():
    digest, name = line.split(maxsplit=1)
    path = OUT / name
    if not path.exists():
        gone.append(name)
    elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        changed.append(name)
print(f"[3] of {len(PRE_HASHES.read_text().splitlines())} files hashed before stage 3: changed {changed}, removed {gone}")
check(not gone and set(changed) <= {"./preprocessing_fingerprints.json"}, "[3] no earlier file changed or removed, except the fingerprint registry, which stage 3 extends")
stage1_fp = {  # Printed after stage 1 (2026-11-25), before any later stage ran.
    "seed0:holdout:bot:reference": "79b5efe5121672f70968a8c8f0f79740b8ec31ef60b4978412dd9a57a59ef874",
    "seed0:holdout:brute_force:reference": "a7060d2b156a4bc1b44f31d1f3a414a17a8892d94ab3e19278cd4b713aa0ef9f",
    "seed0:holdout:dos:reference": "7a0d6e707455e5fd57c9e540efb8e9ffae0263ac1b0e64e4abb6e70f3d7408dd",
    "seed0:holdout:portscan:reference": "30d17f99fa9e1c09c5ddff0547b8be9aa06030ca0a90aa8e6d3a014857099384",
    "seed0:seen:reference": "49610aefc1e108f187fec99b5bf31f3167b2da89cfb2121ddfd1b6638971e1d9",
}
check(all(fp.get(k) == v for k, v in stage1_fp.items()), "[3] the 5 stage-1 fingerprints are unchanged in the registry")

# --- 4. Identities ---
check(frozen_digest() == "25685b84dd83f65c", f"[4] Config A identity {frozen_digest()}")
check(identity.digest() == "7b900fea59b6cf35", f"[4] Config B identity {identity.digest()} equals the signed addendum")
print("POST-STAGE-3 CHECKS: " + ("ALL PASSED" if ok else "FAILURES ABOVE"))
