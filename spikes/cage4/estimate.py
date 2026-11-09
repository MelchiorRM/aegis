"""Compute plan for the Config B experiment, from measured wall times. Planning code only; it runs no model.

What the numbers are, and are not:
- Fit costs are Phase 1's measured Random Forest WALL minutes per fit at 8 workers: improved CICIDS2017 0.76
  (results/config_a_exploratory_improved_amended), UNSW-NB15 0.26 (results/config_a_artifacts_unsw_views).
- They are converted to CPU-hours as wall x 8 cores. That is a ceiling, not a measurement of CPU time: a fit
  cannot use more than 8 cores' worth of CPU per wall second. The experiment's budget is enforced on CPU time
  measured during the run (see docs/config-b-design.md, section 3.5), starting with the calibration stage.
- Replayed arms are charged for their largest training set (fit time taken as linear in training rows).
- Simulator cost is the spike's measured single-worker episode time.

Revision history:
- Spike estimate: about 100 CPU-h.
- 2026-11-10, final plan: stage 0 is the recorded scenario bank (250 episodes, reused; owner approval), measured
  at 3.24 CPU-h and counted against the budget as already spent. Under the final mapping nothing is mapped on
  UNSW-NB15, so B = B0 = A there by construction; `--scope cicids` charges Config B's fits on improved
  CICIDS2017 only, `--scope both` keeps the previously approved scope.
- 2026-11-09, first plan: 181.6 CPU-h with B0's selection and audit (owner decision). It charged nested selection
  one fit per ORDERED family pair. aegis.experiments.selection fits each UNORDERED pair once and scores it in
  both directions, so selection was counted twice. Corrected below.
"""

import sys

BUDGET_CPU_HOURS = 180.0
PLANNING_CEILING = 0.85 * BUDGET_CPU_HOURS  # The plan must fit under 153 CPU-h: a 15% safety margin.
SEEDS = 5
DATASETS = {
    # (outer fits per seed: one with every family seen plus one per held-out family, held-out families,
    #  shortcut treatments, RF wall-min per fit, largest replay growth: replayed rows / Config A training rows)
    "cicids2017_improved": (5, 4, 5, 0.76, 8_838 / 209_000),
    "unsw_nb15": (9, 8, 8, 0.26, 15_271 / 90_000),
}
RF_WORKERS = 8
SIM_BANK_CPU_HOURS = 11_657.0 / 3600  # Measured (RUSAGE_CHILDREN), results/config_b_evidence/scenarios_run.console.log.
RATIOS = (0.25, 0.5, 1.0)


SCOPE = DATASETS


def cpu_ceiling_hours(fits: dict[str, int], ratio: float = 0.0) -> float:
    return sum(n * v[3] * RF_WORKERS * (1 + v[4] * ratio) for d, n in fits.items() for v in [DATASETS[d]]) / 60


def outer(arms: int = 1) -> dict[str, int]:
    return {d: arms * SEEDS * v[0] for d, v in SCOPE.items()}


def audit() -> dict[str, int]:
    return {d: SEEDS * v[1] * v[2] for d, v in SCOPE.items()}


def selection_hours(ratios: tuple[float, ...] = RATIOS) -> float:
    # One fit per unordered pair of eligible families, per seed, per candidate ratio.
    fits = {d: SEEDS * v[1] * (v[1] - 1) // 2 for d, v in SCOPE.items()}
    return sum(cpu_ceiling_hours(fits, r) for r in ratios)


def plan() -> list[tuple[str, str, float]]:
    top = max(RATIOS)
    arms = cpu_ceiling_hours(outer()) + 2 * cpu_ceiling_hours(outer(), top)
    return [
        ("0", "Scenario bank: 50 episodes x 5 fold seeds, reused (measured, already spent)", SIM_BANK_CPU_HOURS),
        ("1", "Calibration: seed 0 outer folds, A, B, B0 (kept as part of stage 3); CPU time measured", arms / SEEDS),
        ("2a", f"Nested selection of B ({len(RATIOS)} ratios)", selection_hours()),
        ("2b", f"Nested selection of B0 ({len(RATIOS)} ratios, same rule)", selection_hours()),
        ("3", "Outer folds: A, B, B0, seeds 1-4", arms * (SEEDS - 1) / SEEDS),
        ("4a", "Shortcut audit of B", cpu_ceiling_hours(audit(), top)),
        ("4b", "Shortcut audit of B0", cpu_ceiling_hours(audit(), top)),
        ("4c", "Shortcut audit of A under 25685b84dd83f65c (Phase 1 audit not reusable)", cpu_ceiling_hours(audit())),
        ("5", "Determinism rerun: A, B, B0 outer folds, all seeds", arms),
        ("6", "Perturbation arm (exploratory), outer folds", cpu_ceiling_hours(outer(), top)),
    ]


def main() -> None:
    global SCOPE
    scope = sys.argv[sys.argv.index("--scope") + 1] if "--scope" in sys.argv else "cicids"
    SCOPE = {d: v for d, v in DATASETS.items() if scope == "both" or d == "cicids2017_improved"}
    print(f"Scope: {scope} ({', '.join(SCOPE)})")
    parts = plan()
    width = max(len(n) for _, n, _ in parts)
    running = 0.0
    for stage, name, hours in parts:
        running += hours
        print(f"{stage:<3} {name:<{width}}  {hours:6.1f}   cumulative {running:6.1f}")
    print(f"{'':<3} {'Total, CPU-h ceiling (wall x 8)':<{width}}  {running:6.1f}")
    print(f"Budget {BUDGET_CPU_HOURS:.0f}; planning ceiling {PLANNING_CEILING:.0f} (15% margin); "
          f"margin to budget {BUDGET_CPU_HOURS - running:.1f} ({(BUDGET_CPU_HOURS - running) / BUDGET_CPU_HOURS:.0%})")
    print(f"About {running / RF_WORKERS:.0f} h wall on 8 cores, one fit at a time")
    print(f"Fits within the planning ceiling: {running <= PLANNING_CEILING}")
    print(f"For reference: 2 candidates (0.25, 1.0) would save {2 * (selection_hours() - selection_hours((0.25, 1.0))):.1f}"
          " (not proposed)")


if __name__ == "__main__":
    main()
