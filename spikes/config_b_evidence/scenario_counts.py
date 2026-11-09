"""Scenario action counts for every planned simulator seed (owner approval 2026-11-09). Descriptive only.

Runs the unchanged spike probe (spikes/cage4/probe.py) in the isolated spike environment, blue Sleep, 500 steps,
for simulator seed = 1000 x fold seed + episode index (fold seeds 0-4, episodes 0-49), at most 2 concurrent
workers. Then counts executed red actions under the draft's outcome rules. Loads no dataset, fits no model,
generates no training data. CPU time is measured (RUSAGE_CHILDREN after every worker has been joined).

    .venv/bin/python spikes/config_b_evidence/scenario_counts.py run        # episodes -> ~/aegis-spike/runs/config_b_seeds
    .venv/bin/python spikes/config_b_evidence/scenario_counts.py summarize  # counts -> results/config_b_evidence/scenarios
"""

from __future__ import annotations

import collections
import json
import resource
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPIKE = Path.home() / "aegis-spike"
RUNS = SPIKE / "runs" / "config_b_seeds"
OUT = ROOT / "results" / "config_b_evidence" / "scenarios"
FOLD_SEEDS, EPISODES, WORKERS = range(5), range(50), 2
# Approved mapping candidates on improved CICIDS2017 (HTTPRFI unmapped; UNSW-NB15 unmapped).
MAPPED = {("ExploitRemoteService", "SSHBruteForce"): "brute_force",
          ("ExploitRemoteService", "SQLInjection"): "web_attack",
          ("AggressiveServiceDiscovery", None): "portscan",
          ("StealthServiceDiscovery", None): "portscan"}


def sim_seed(fold_seed: int, episode: int) -> int:
    if not 0 <= episode < 1000:
        raise ValueError("episode index must be in [0, 1000) for the seed derivation to stay unique")
    return 1000 * fold_seed + episode


def run_one(seed: int) -> dict:
    out = RUNS / f"seed_{seed:04d}.jsonl"
    summary = RUNS / f"seed_{seed:04d}.summary.json"
    if summary.exists():
        return json.loads(summary.read_text())
    done = subprocess.run([str(SPIKE / "venv" / "bin" / "python"), str(ROOT / "spikes" / "cage4" / "probe.py"),
                           "--seed", str(seed), "--steps", "500", "--blue", "sleep", "--out", str(out)],
                          capture_output=True, text=True, check=True)
    summary.write_text(done.stdout)
    return json.loads(done.stdout)


def run() -> None:
    seeds = [sim_seed(f, e) for f in FOLD_SEEDS for e in EPISODES]
    if len(set(seeds)) != len(seeds):
        raise SystemExit("STOP: simulator seeds are not unique")
    RUNS.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        list(pool.map(run_one, seeds))
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    ledger = {"episodes": len(seeds), "workers": WORKERS, "wall_seconds": round(time.time() - started, 1),
              "cpu_seconds_children": round(usage.ru_utime + usage.ru_stime, 1),
              "note": "CPU covers episodes run in this invocation only (cached summaries are skipped)."}
    (RUNS / "ledger.json").write_text(json.dumps(ledger, indent=2))
    print(json.dumps(ledger, indent=2))


def classify(action: dict, success: str) -> str:
    if action["type"] == "ExploitRemoteService" and "sub_action" not in action:
        return "O4_unreachable"  # Failed before any exploit or service was chosen.
    if success == "UNKNOWN":
        return "O6_unknown"
    return "attempt"


def summarize() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows, hashes = [], {}
    for fold_seed in FOLD_SEEDS:
        for episode in EPISODES:
            seed = sim_seed(fold_seed, episode)
            hashes[seed] = json.loads((RUNS / f"seed_{seed:04d}.summary.json").read_text())["trajectory_sha256"]
            counts = collections.Counter()
            with open(RUNS / f"seed_{seed:04d}.jsonl", encoding="utf-8") as handle:
                for line in handle:
                    record = json.loads(line)
                    for red in record["red"].values():
                        for action in red["actions"]:
                            if action["type"] == "Sleep":
                                continue  # In-progress ticks appear as Sleep: never counted (O1).
                            kind = classify(action, red["success"])
                            sub = action.get("sub_action")
                            counts[("all_red", "", "")] += 1
                            counts[(action["type"], sub or "", kind)] += 1
                            if kind == "attempt" and red["success"] == "TRUE":
                                counts[(action["type"], sub or "", "success")] += 1
                            family = MAPPED.get((action["type"], sub if action["type"] == "ExploitRemoteService" else None))
                            if family and kind == "attempt":
                                counts[("mapped", family, "attempt")] += 1
            for (a, s, k), n in counts.items():
                rows.append({"fold_seed": fold_seed, "episode": episode, "sim_seed": seed,
                             "action": a, "sub_action": s, "kind": k, "count": n})
    import pandas as pd  # Aegis environment.
    table = pd.DataFrame(rows)
    table.to_csv(OUT / "episode_counts.csv", index=False)
    (OUT / "trajectory_hashes.json").write_text(json.dumps(hashes, indent=2))
    per_seed = (table.groupby(["fold_seed", "action", "sub_action", "kind"])["count"].sum()
                .unstack("fold_seed", fill_value=0))
    per_seed["total"] = per_seed.sum(axis=1)
    per_seed.to_csv(OUT / "per_fold_seed_counts.csv")
    print(per_seed.to_string())
    focus = table[(table.action == "ExploitRemoteService") & (table.sub_action == "SQLInjection") & (table.kind == "attempt")]
    per_episode = focus.groupby("sim_seed")["count"].sum().reindex(sorted(hashes), fill_value=0)
    per_episode.to_csv(OUT / "sqlinjection_attempts_per_episode.csv", header=["attempts"])
    print("\nSQLInjection attempts per episode: mean %.2f, min %d, max %d, zero in %d of %d episodes"
          % (per_episode.mean(), per_episode.min(), per_episode.max(), (per_episode == 0).sum(), len(per_episode)))


if __name__ == "__main__":
    {"run": run, "summarize": summarize}[sys.argv[1]]()
