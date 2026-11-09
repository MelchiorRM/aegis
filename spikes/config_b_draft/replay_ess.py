"""Replay arithmetic for the DRAFT Config B mapping: allocation, the per-row cap, and effective sample size.

Design arithmetic only, for the owner's review. It loads no dataset, fits no model and generates no training
data. Inputs, both illustrations:
- the cleaned family counts recorded in Config A's manifest (results/config_a_improved_25685b84dd83f65c),
  split as make_partition does (20% test, 20% validation, the rest training) and capped at 100,000 per family;
- the mapped red-event counts of one spike episode (seed 0, blue Sleep, 500 steps), counted once per executed
  action under the draft's outcome rules.
The experiment computes the same quantities per fold and per seed from its own rows and episodes.

Definitions (docs/config-b-mapping-draft.md, section 4):
- B: total R = r x (training rows of the mapped, seen families), split in proportion to mapped event counts,
  then capped at CAP_PER_ROW replays per training row; the excess is dropped (truncated), not redistributed.
- B0: the same total as B's realized total, drawn uniformly from the pool of all seen attack training records.
  Its expected family split is proportional to family size, which is what is used here.
- Weight of a record = 1 + number of times it is replayed. Kish effective sample size = (sum w)^2 / sum w^2.
"""

from __future__ import annotations

CAP = 100_000
CAP_PER_ROW = 4
COUNTS = {
    "cicids2017_improved": {"bot": 736, "brute_force": 6933, "dos": 266778, "heartbleed": 11, "infiltration": 36,
                            "portscan": 7695, "web_attack": 104},
    "unsw_nb15": {"analysis": 450, "backdoor": 350, "dos": 3624, "exploits": 25451, "fuzzers": 18749,
                  "generic": 7283, "reconnaissance": 8419, "shellcode": 1446, "worms": 159},
}
HELD_OUT = {
    "cicids2017_improved": ["bot", "brute_force", "dos", "portscan"],
    "unsw_nb15": ["analysis", "backdoor", "dos", "exploits", "fuzzers", "generic", "reconnaissance", "shellcode"],
}
SCENARIOS = {
    # Approved by the owner on 2026-11-09: SSHBruteForce, SQLInjection, both service discoveries (CICIDS2017 only).
    "approved only": {
        "cicids2017_improved": {"brute_force": 52, "web_attack": 6, "portscan": 45 + 40},
        "unsw_nb15": {},
    },
    # If every provisional entry were later supported (HTTPRFI on both datasets; SQLInjection on UNSW-NB15).
    "approved + provisional": {
        "cicids2017_improved": {"brute_force": 52, "web_attack": 6 + 11, "portscan": 45 + 40},
        "unsw_nb15": {"exploits": 6 + 11},
    },
}
RATIOS = (0.25, 0.5, 1.0)


def train_rows(n: int) -> int:
    return min(n - 2 * int(round(n * 0.2)), CAP)


def sums(n: int, m: int) -> tuple[int, int]:
    """Sum of weights and of squared weights: n records, m replays dealt cyclically without replacement."""
    k, q = divmod(m, n)
    return n + m, (n - q) * (1 + k) ** 2 + q * (2 + k) ** 2


def kish(parts: list[tuple[int, int]]) -> float:
    s = s2 = 0
    for n, m in parts:
        a, b = sums(n, m)
        s, s2 = s + a, s2 + b
    return s * s / s2


def allocate(total: int, shares: dict[str, float]) -> dict[str, int]:
    weight = sum(shares.values())
    return {f: int(round(total * v / weight)) for f, v in shares.items()} if weight else {}


def main() -> None:
    print("Illustration only: Config A cleaned counts, one seed-0 episode. Not the experiment's numbers.")
    for scenario, events in SCENARIOS.items():
        print(f"\n######## {scenario}")
        for dataset, counts in COUNTS.items():
            print(f"== {dataset}")
            for held in HELD_OUT[dataset]:
                seen = {f: train_rows(n) for f, n in counts.items() if f != held}
                mapped = {f: e for f, e in events[dataset].items() if f in seen}
                if not mapped:
                    print(f"  held out {held:<15} no mapped seen family: B = A (B0 = A, nothing to match)")
                    continue
                for r in RATIOS:
                    requested = allocate(int(round(r * sum(seen[f] for f in mapped))), mapped)
                    b = {f: min(m, CAP_PER_ROW * seen[f]) for f, m in requested.items()}
                    truncated = {f: requested[f] - b[f] for f in b if requested[f] > b[f]}
                    realized = sum(b.values())
                    b0 = allocate(realized, seen)
                    ess = [kish([(n, plan.get(f, 0)) for f, n in seen.items()]) for plan in ({}, b, b0)]
                    detail = ", ".join(f"{f} {b[f]:,}/{seen[f]:,} (ESS {kish([(seen[f], b[f])]):,.0f})" for f in sorted(b))
                    cut = ", ".join(f"{f} {t:,}" for f, t in truncated.items()) or "none"
                    print(f"  held out {held:<15} r={r:<4} requested {sum(requested.values()):>6,} realized {realized:>6,}"
                          f" truncated: {cut}")
                    print(f"      B replays/rows: {detail}")
                    print(f"      attack-class ESS  A {ess[0]:>9,.0f}   B {ess[1]:>9,.0f}   B0 {ess[2]:>9,.0f}")


if __name__ == "__main__":
    main()
