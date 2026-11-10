"""Every fixed value of the registered Config B protocol, in one place.

Each constant cites the section of ``docs/preregistration/config_b.md`` that sets it. Changing one is a protocol
change: it needs a dated, signed amendment before the stage it affects, and it changes the Config B identity.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
AMENDMENT = ROOT / "docs" / "preregistration" / "config_b.json"  # Registered 2026-11-10T07:51:06Z.

# Section 2: Scope A, improved CICIDS2017 only.
DATASET = "cicids2017_improved"
HELD_OUT_FAMILIES = ("bot", "brute_force", "dos", "portscan")
FOLD_SEEDS = (0, 1, 2, 3, 4)

# Section 4: the scenario bank, reused (50 episodes per fold seed).
EPISODES_PER_FOLD_SEED = 50
MAX_EPISODES = 1000  # The seed rule is unique only while the episode index stays below 1000.
BANK_MANIFEST = ROOT / "spikes" / "config_b_evidence" / "scenario_bank_manifest.json"
BANK_MANIFEST_SHA256 = "11021c5d6371f7744962b2b868e3b86052d28e32a02a0a5aea6c0203f13c222e"
DEFAULT_BANK_DIR = Path.home() / "aegis-spike" / "runs" / "config_b_seeds"
BANK_STEPS = 499
BANK_BLUE = "sleep"

# Section 5: the final mapping. Keys are (action type, sub-action); the sub-action matters for exploits only.
MAPPING = {
    ("ExploitRemoteService", "SSHBruteForce"): "brute_force",
    ("AggressiveServiceDiscovery", ""): "portscan",
    ("StealthServiceDiscovery", ""): "portscan",
}
MAPPED_FAMILIES = ("brute_force", "portscan")

# Section 6: arms and replay.
ARMS = ("A", "B", "B0")
MAX_REPLAYS_PER_ROW = 4  # A guard; it does not bind under this mapping.

# Section 8: ratio selection. The first candidate is the default.
RATIOS = (0.25, 0.5, 1.0)
CANDIDATES = tuple(f"{r:g}" for r in RATIOS)  # ("0.25", "0.5", "1")

# Section 9.3: the shortcut audit.
RULE_TREATMENTS = ("remove_matching_signatures", "no_tcp_window", "neutralize_missing_markers", "all_controls")
OUTSIDE_RULE = ("missingness_only",)
REFERENCE = "reference"

# Section 6.1: fold groups. Inner folds are (outer held-out family, inner held-out family).
FOLD_GROUPS = {"two_family": ("bot", "dos"), "single_family": ("brute_force", "portscan")}

# Section 12: compute. Stage ceilings are spikes/cage4/estimate.py --scope cicids (CPU-h, wall x 8 cores).
STAGE0_SPENT_CPU_HOURS = 11_657.0 / 3600  # Measured bank cost, already spent.
STAGES = ("1", "2a", "2b", "3", "4a", "4b", "4c", "5")  # Stage 6 (perturbation) is excluded (section 11).
# Proposed Config B amendment 1 (G2): stage 1 fits arm A only (5 fits at 0.76 wall-min x 8 cores = 0.506667), so
# B's and B0's seed-0 outer folds move to stage 3 (6.251404 + 1.562851 - 0.506667). The total is unchanged, 68.8.
STAGE_CEILINGS = {
    "1": 0.506667, "2a": 9.344967, "2b": 9.344967, "3": 7.307588,
    "4a": 10.561842, "4b": 10.561842, "4c": 10.133333, "5": 7.814255,
}
APPROVED_PLANNING_BUDGET = 71.5
PLANNING_CEILING = 153.0
IN_STAGE_STOP = 175.0
HARD_STOP = 180.0


def sim_seed(fold_seed: int, episode: int) -> int:
    """Simulator seed = 1000 x fold seed + episode index (section 4). Refuses inputs that could collide."""
    if not 0 <= episode < MAX_EPISODES:
        raise ValueError(f"episode index {episode} must be in [0, {MAX_EPISODES}) for the seed rule to stay unique")
    if fold_seed < 0:
        raise ValueError(f"fold seed {fold_seed} must be non-negative")
    return 1000 * fold_seed + episode


def bank_seeds() -> list[tuple[int, int, int]]:
    """Every (fold seed, episode, simulator seed) of the bank."""
    return [(f, e, sim_seed(f, e)) for f in FOLD_SEEDS for e in range(EPISODES_PER_FOLD_SEED)]


def fold_group(outer: str, inner: str | None = None) -> str:
    """The fold group of an outer fold, or of an inner selection fold (section 6.1).

    The group depends on how many mapped families the fold trains on.
    """
    held = {outer} if inner is None else {outer, inner}
    remaining = [f for f in MAPPED_FAMILIES if f not in held]
    return {2: "two_family", 1: "single_family", 0: "neither_family"}[len(remaining)]
