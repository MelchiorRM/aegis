"""Read-only pre-stage-3 checks. Writes nothing into the repository or results."""
import hashlib, json, os, re
from pathlib import Path

import pandas as pd

from aegis.config import load_config
from aegis.config_b import analysis, identity, protocol
from aegis.config_b.compute import Ledger
from aegis.experiments.baseline import FoldStore
from aegis.experiments.selection import select
from aegis.frozen import frozen_digest

OUT = Path("results/config_b")
config = load_config(Path("configs/baseline.yaml"))
primary = config.target_fprs[0]
fams = set(protocol.HELD_OUT_FAMILIES)
seeds = set(protocol.FOLD_SEEDS)
ok = True


def check(cond, msg):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + msg)


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


print(f"primary target FPR = {primary}; candidates = {protocol.CANDIDATES}; seen-fold ratio = {protocol.SEEN_FOLD_RATIO}")

# 1. Selection CSVs
inner_all = FoldStore(OUT / "selection").load_all()
for arm in ("B", "B0"):
    csv = pd.read_csv(OUT / f"selections_{arm}.csv", dtype={"selected": str})
    keys = list(zip(csv.seed, csv.outer_family))
    check(len(csv) == 20, f"[1] {arm}: {len(csv)} rows")
    check(len(set(keys)) == 20, f"[1] {arm}: {len(set(keys))} distinct seed/family pairs")
    check(set(csv.seed) == seeds and set(csv.outer_family) == fams, f"[1] {arm}: seeds {sorted(set(csv.seed))}, families {sorted(set(csv.outer_family))}")
    check(set(csv.selected) <= set(protocol.CANDIDATES), f"[1] {arm}: every selection is a registered candidate {sorted(set(csv.selected))}")
    check((csv.n_inner_families == 3).all(), f"[1] {arm}: 3 inner families in every cell")
    means = [c for c in csv.columns if c.startswith("mean_inner_recall_")]
    check(not csv[means].isna().any().any(), f"[1] {arm}: no missing mean inner recall")
    check((csv.dataset == "cicids2017_improved").all(), f"[1] {arm}: dataset cicids2017_improved only")

    # Recompute exactly as Runner.selected does, from the inner store that stage 3 reads.
    rows = inner_all[inner_all["arm"] == arm].copy()
    rows["candidate"] = rows["candidate"].astype(str).map(lambda c: f"{float(c):g}")
    again = select(rows, primary, protocol.CANDIDATES)
    merged = csv.merge(again, on=["dataset", "seed", "outer_family"], suffixes=("_csv", "_now"))
    check(len(merged) == 20 and (merged.selected_csv == merged.selected_now.astype(str)).all(),
          f"[1] {arm}: CSV equals a fresh recomputation from selection/ (20 of 20)")

    # 2. What stage 3 will consume, replicating Runner.candidates_for
    print(f"[2] {arm}: ratio each outer fold will use (seen fold = fixed default {protocol.SEEN_FOLD_RATIO:g})")
    table = {}
    for seed in sorted(seeds):
        chosen = again[again["seed"] == seed].set_index("outer_family")["selected"]
        cand = {None: f"{protocol.SEEN_FOLD_RATIO:g}", **{f: f"{float(chosen[f]):g}" for f in protocol.HELD_OUT_FAMILIES}}
        table[seed] = {"seen": cand[None], **{f: cand[f] for f in protocol.HELD_OUT_FAMILIES}}
        src = csv[csv.seed == seed].set_index("outer_family")["selected"]
        check(all(cand[f] == f"{float(src[f]):g}" for f in protocol.HELD_OUT_FAMILIES),
              f"[2] {arm} seed {seed}: consumed ratios match the CSV row for each held-out family")
    print(pd.DataFrame(table).T.rename_axis("seed").to_string())

# Selection files: arm, seed and pair agree with their file names
pat = re.compile(r"__seed(\d)__(B0?)_pair_(.+)\.csv$")
files = sorted((OUT / "selection").glob("*.csv"))
bad = 0
for p in files:
    m = pat.search(p.name)
    df = pd.read_csv(p)
    seed, arm = int(m.group(1)), m.group(2)
    if not ((df.seed == seed).all() and (df.arm == arm).all()):
        bad += 1
    if not (df.outer_family != df.inner_family).all():
        bad += 1
check(len(files) == 60 and bad == 0, f"[2] selection/: {len(files)} files, arm and seed columns match file names, outer != inner in every row")

# 3. Neither-family control
ctrl_path = OUT / "neither_family_control.json"
saved = json.loads(ctrl_path.read_text())
again = analysis.neither_family_control(inner_all)
check(saved == again, f"[3] neither-family control recomputes identically: {again}")
part = inner_all[inner_all["fold_group"] == "neither_family"]
check(set(part.arm) == {"B", "B0"} and (part.replay_total == 0).all(), f"[3] control covers arms {sorted(set(part.arm))}, all {len(part)} rows with zero replay")
print(f"[3] artifact preserved: {ctrl_path} sha256 {sha(ctrl_path)[:16]}, modified {pd.Timestamp(os.path.getmtime(ctrl_path), unit='s', tz='UTC')}")

# 4. Identities and ledger
check(frozen_digest() == "25685b84dd83f65c", f"[4] Config A identity {frozen_digest()}")
check(identity.digest() == "7b900fea59b6cf35", f"[4] Config B identity {identity.digest()} equals the signed addendum")
a = identity.authorization("3")
check(a == {"approved_budget": 71.5, "past_planning_ceiling": False}, f"[4] stage 3 is in the recorded authorization; approvals {a}")
ledger = Ledger(OUT / "compute_ledger.csv", a["approved_budget"], a["past_planning_ceiling"])
done = [s for s in protocol.STAGES if (OUT / f"stage_{s}.done").exists()]
p = ledger.before_stage("3", done)
print(f"[4] ledger: finished {done}; spent {ledger.total_hours():.3f} CPU-h; by stage "
      f"{ {s: round(ledger.measured_hours(s), 3) for s in done} }; ratio {p['ratio_measured_to_ceiling']:.4f}; "
      f"stage 3 estimate {p['remaining_estimates']['3']:.3f} (ceiling {protocol.STAGE_CEILINGS['3']}); "
      f"projected {p['projected_total']:.2f} of {p['approved_budget']}")

# 5. Separation: what is in the outer-fold store, and what selection reads
outer = FoldStore(OUT / "folds").load_all()
check(set(outer.arm) == {"A"} and set(outer.seed) == {0}, f"[5] folds/ holds only arm A seed 0 ({len(outer)} rows); no B or B0 outer results exist yet")
print("PRE-STAGE-3 CHECKS: " + ("ALL PASSED" if ok else "FAILURES ABOVE"))
