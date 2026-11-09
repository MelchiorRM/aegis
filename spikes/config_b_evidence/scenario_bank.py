"""Record the Config B simulator scenario bank (owner approval 2026-11-10: reuse the 250 existing episodes).

The bank is 50 episodes for each of five fold seeds (simulator seed = 1000 x fold seed + episode index), not 250
independent seeds, and it is not an independent validation set. This script reads the episode logs only: it
records the CAGE commit, configuration, seeds, episode count, every log's SHA-256, and action counts recomputed
from the checksummed logs and verified against the earlier summary (results/config_b_evidence/scenarios/). It
also checksums the original spike artifacts, which stay where they are, unchanged. It runs no simulator, loads
no dataset and fits no model.

    .venv/bin/python spikes/config_b_evidence/scenario_bank.py
"""

from __future__ import annotations

import collections
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
SPIKE = Path.home() / "aegis-spike"
BANK = SPIKE / "runs" / "config_b_seeds"
OUT = ROOT / "spikes" / "config_b_evidence" / "scenario_bank_manifest.json"
EARLIER = ROOT / "results" / "config_b_evidence" / "scenarios" / "episode_counts.csv"
FOLD_SEEDS, EPISODES = range(5), range(50)
MAPPED = {("ExploitRemoteService", "SSHBruteForce"): "brute_force",
          ("AggressiveServiceDiscovery", ""): "portscan",
          ("StealthServiceDiscovery", ""): "portscan"}  # Final mapping, owner 2026-11-10.


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def count(path: Path) -> collections.Counter:
    counts = collections.Counter()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            for red in json.loads(line)["red"].values():
                for action in red["actions"]:
                    if action["type"] == "Sleep":
                        continue
                    sub = action.get("sub_action", "")
                    if action["type"] == "ExploitRemoteService" and not sub:
                        counts[("ExploitRemoteService", "", "O4_unreachable")] += 1
                        continue
                    counts[(action["type"], sub, "attempt")] += 1
                    if red["success"] == "TRUE":
                        counts[(action["type"], sub, "success")] += 1
                    key = (action["type"], sub if action["type"] == "ExploitRemoteService" else "")
                    if key in MAPPED:
                        counts[("mapped", MAPPED[key], "attempt")] += 1
    return counts


def main() -> None:
    episodes, per_seed = [], {f: collections.Counter() for f in FOLD_SEEDS}
    for fold_seed in FOLD_SEEDS:
        for episode in EPISODES:
            seed = 1000 * fold_seed + episode
            log = BANK / f"seed_{seed:04d}.jsonl"
            summary = json.loads((BANK / f"seed_{seed:04d}.summary.json").read_text())
            if summary["seed"] != seed or summary["steps"] != 499 or summary["blue"] != "sleep":
                raise SystemExit(f"STOP: summary of seed {seed} does not match the bank configuration")
            counts = count(log)
            per_seed[fold_seed].update(counts)
            episodes.append({"fold_seed": fold_seed, "episode": episode, "sim_seed": seed,
                             "log_sha256": sha256(log), "trajectory_sha256": summary["trajectory_sha256"],
                             "mapped_brute_force": counts[("mapped", "brute_force", "attempt")],
                             "mapped_portscan": counts[("mapped", "portscan", "attempt")]})

    # Verify against the earlier summary, computed before this record.
    earlier = pd.read_csv(EARLIER).fillna("")
    for fold_seed in FOLD_SEEDS:
        part = earlier[earlier.fold_seed == fold_seed]
        for key in [("ExploitRemoteService", "SSHBruteForce", "attempt"), ("AggressiveServiceDiscovery", "", "attempt"),
                    ("StealthServiceDiscovery", "", "attempt"), ("ExploitRemoteService", "", "O4_unreachable"),
                    ("Impact", "", "attempt"), ("DegradeServices", "", "attempt")]:
            before = int(part[(part.action == key[0]) & (part.sub_action == key[1]) & (part.kind == key[2])]["count"].sum())
            if before != per_seed[fold_seed][key]:
                raise SystemExit(f"STOP: fold seed {fold_seed} {key}: {per_seed[fold_seed][key]} now, {before} before")

    totals = {}
    for fold_seed, c in per_seed.items():
        red = sum(n for (a, s, k), n in c.items() if a != "mapped" and k in ("attempt", "O4_unreachable"))
        bf, ps = c[("mapped", "brute_force", "attempt")], c[("mapped", "portscan", "attempt")]
        totals[str(fold_seed)] = {
            "red_actions": red, "brute_force": bf, "portscan": ps,
            "weight_brute_force": round(bf / (bf + ps), 6), "weight_portscan": round(ps / (bf + ps), 6),
            "sql_injection_attempts_unmapped": c[("ExploitRemoteService", "SQLInjection", "attempt")],
            "http_rfi_attempts_unmapped": c[("ExploitRemoteService", "HTTPRFI", "attempt")],
            "unreachable_exploits_O4": c[("ExploitRemoteService", "", "O4_unreachable")],
            "impact": c[("Impact", "", "attempt")], "degrade_services": c[("DegradeServices", "", "attempt")],
        }
    spike_artifacts = {p.name: sha256(p) for p in sorted((SPIKE / "runs").glob("*.json*")) if p.is_file()}
    manifest = {
        "name": "Config B simulator scenario bank",
        "status": "recorded 2026-11-10 for owner review; not frozen until the pre-registration amendment",
        "description": "50 episodes for each of five fold seeds (not 250 independent seeds). CAGE 4 scripted red "
                       "(FiniteStateRedAgent) against sleeping blue. Not a real-world attacker population and not an "
                       "independent validation set.",
        "cage": {"repository": "https://github.com/cage-challenge/cage-challenge-4",
                 "commit": subprocess.run(["git", "-C", str(SPIKE / "cc4"), "rev-parse", "HEAD"], capture_output=True,
                                          text=True).stdout.strip(),
                 "package_metadata_version": "4.0",
                 "lock_sha256": sha256(ROOT / "spikes" / "cage4" / "requirements.lock")},
        "configuration": {"generator": "EnterpriseScenarioGenerator", "red_agent_class": "FiniteStateRedAgent",
                          "green_agent_class": "EnterpriseGreenAgent", "blue_agent_class": "SleepAgent",
                          "blue_policy": "Sleep for all five blue agents", "steps": 500, "executed_steps": 499,
                          "probe": "spikes/cage4/probe.py", "probe_sha256": sha256(ROOT / "spikes" / "cage4" / "probe.py"),
                          "python": platform.python_version(), "workers": 2},
        "seeds": {"rule": "sim_seed = 1000 * fold_seed + episode", "fold_seeds": list(FOLD_SEEDS),
                  "episodes_per_fold_seed": len(EPISODES), "episode_count": len(episodes),
                  "unique_sim_seeds": len({e["sim_seed"] for e in episodes}),
                  "unique_trajectories": len({e["trajectory_sha256"] for e in episodes})},
        "outcome_rules": "each executed action once; in-progress steps (logged as Sleep) never; ExploitRemoteService "
                         "with no concrete exploit = O4 unreachable, reported separately",
        "verified_against": "results/config_b_evidence/scenarios/episode_counts.csv (all compared counts equal)",
        "per_fold_seed": totals,
        "episodes": episodes,
        "original_spike_artifacts_sha256": spike_artifacts,
        "reproducibility": {
            "behavioural": "seed 0, 2 and 3 behavioural counts (red actions, successes, blue events, reward) equal the "
                           "spike's runs exactly",
            "byte_for_byte": "seed 0 trajectory hash equals the spike's final-probe hash (724e864d...); seeds 2 and 3 "
                             "differ from the spike's hashes because those runs predate sub_action logging, a change in "
                             "what is logged, not in behaviour",
        },
    }
    OUT.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: manifest[k] for k in ("cage", "seeds", "per_fold_seed")}, indent=2))


if __name__ == "__main__":
    main()
