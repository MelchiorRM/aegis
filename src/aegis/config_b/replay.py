"""Replay allocation for B and B0, and the effective-sample-size report (section 6).

A replay is the index of a training row that is copied once more. Replays are drawn only from the training rows
passed in, which are Config A's capped training rows for the fold, inner fold or treatment. So no arm gains a
distinct record.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from aegis.config_b import protocol
from aegis.data.dataset import BENIGN

ARM_STREAM = {"B": 1, "B0": 2}  # Separate random streams, so B and B0 never share draws.


@dataclass
class Replay:
    """The replays one arm adds to one training set, with the accounting the protocol reports."""

    arm: str
    ratio: float
    copies: np.ndarray  # Training-row indices, one entry per added copy.
    requested: dict[str, int] = field(default_factory=dict)
    realized: dict[str, int] = field(default_factory=dict)
    truncated: dict[str, int] = field(default_factory=dict)
    excluded_held_out: dict[str, int] = field(default_factory=dict)  # Events of mapped families not in training.
    weights: dict[str, float] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return int(len(self.copies))


def _rng(fold_seed: int, arm: str, stream: int) -> np.random.Generator:
    return np.random.default_rng(np.random.SeedSequence([fold_seed, ARM_STREAM[arm], stream]))


def cyclic_draws(pool: np.ndarray, m: int, rng: np.random.Generator) -> np.ndarray:
    """``m`` draws from ``pool``, cyclically without replacement: each pass is a fresh permutation."""
    if m == 0 or len(pool) == 0:
        return np.empty(0, dtype=np.int64)
    passes = -(-m // len(pool))
    return np.concatenate([rng.permutation(pool) for _ in range(passes)])[:m].astype(np.int64)


def family_weights(events: dict[str, int], seen: set[str]) -> tuple[dict[str, float], dict[str, int]]:
    """p_f over the mapped families present in training, plus the events excluded as held out or absent."""
    kept = {f: n for f, n in events.items() if f in seen}
    excluded = {f: n for f, n in events.items() if f not in seen}
    total = sum(kept.values())
    return ({f: n / total for f, n in kept.items()} if total else {}), excluded


def allocate_b(train: np.ndarray, family: np.ndarray, events: dict[str, int], ratio: float, fold_seed: int) -> Replay:
    """B: replay split across the seen mapped families by the scenario's event weights (section 6, steps 1-7).

    ``events`` holds the fold seed's mapped event counts from the bank.
    - The requested total is round(ratio x the training rows of the seen mapped families), and family f requests
      round(total x p_f). Both use Python's ``round``, as in the registered illustration.
    - Within a family, draws are cyclic without replacement.
    - At most ``MAX_REPLAYS_PER_ROW`` replays fall on any one row. The excess is truncated, not redistributed.
    """
    labels = family[train].astype(str)
    pools = {f: train[labels == f] for f in protocol.MAPPED_FAMILIES}
    seen = {f for f, rows in pools.items() if len(rows)}
    weights, excluded = family_weights(events, seen)
    replay = Replay("B", ratio, np.empty(0, dtype=np.int64), excluded_held_out=excluded, weights=weights)
    if not weights:
        return replay
    total = int(round(ratio * sum(len(pools[f]) for f in weights)))
    parts = []
    for stream, f in enumerate(protocol.MAPPED_FAMILIES):
        if f not in weights:
            continue
        requested = int(round(total * weights[f]))
        realized = min(requested, protocol.MAX_REPLAYS_PER_ROW * len(pools[f]))
        replay.requested[f], replay.realized[f] = requested, realized
        replay.truncated[f] = requested - realized
        parts.append(cyclic_draws(pools[f], realized, _rng(fold_seed, "B", stream)))
    replay.copies = np.concatenate(parts) if parts else replay.copies
    return replay


def allocate_b0(train: np.ndarray, family: np.ndarray, total: int, ratio: float, fold_seed: int) -> Replay:
    """B0: exactly ``total`` replays (B's realized total), cyclic without replacement over every seen attack row.

    The same per-row cap applies. No simulator information enters. With ``total`` zero, B0 adds nothing.
    """
    labels = family[train].astype(str)
    pool = train[labels != BENIGN]
    realized = min(total, protocol.MAX_REPLAYS_PER_ROW * len(pool))
    copies = cyclic_draws(pool, realized, _rng(fold_seed, "B0", 0))
    drawn = labels_of(copies, family)
    replay = Replay("B0", ratio, copies, requested={"all_seen_attack": total}, truncated={"all_seen_attack": total - realized})
    replay.realized = {f: int((drawn == f).sum()) for f in sorted(set(drawn))}
    return replay


def labels_of(rows: np.ndarray, family: np.ndarray) -> np.ndarray:
    return family[rows].astype(str) if len(rows) else np.empty(0, dtype=str)


def replay_for(arm: str, train: np.ndarray, family: np.ndarray, events: dict[str, int], ratio: float,
               fold_seed: int) -> Replay:
    """The replay of ``arm`` at ``ratio``. B0's total is B's realized total on the same rows and ratio."""
    if arm == "A":
        return Replay("A", 0.0, np.empty(0, dtype=np.int64))
    b = allocate_b(train, family, events, ratio, fold_seed)
    return b if arm == "B" else allocate_b0(train, family, b.total, ratio, fold_seed)


def multiplicities(train: np.ndarray, copies: np.ndarray) -> np.ndarray:
    """1 + the number of replays of each training row, in the order of ``train``."""
    position = {int(r): i for i, r in enumerate(train)}
    counts = np.ones(len(train), dtype=np.int64)
    for row in copies:
        counts[position[int(row)]] += 1
    return counts


def kish(weights: np.ndarray) -> float:
    """Kish's effective sample size, (sum w)^2 / sum w^2. It never exceeds the number of records."""
    w = np.asarray(weights, dtype=float)
    return float(w.sum() ** 2 / (w ** 2).sum()) if len(w) else 0.0


def kish_cyclic(n: int, m: int) -> float:
    """The closed form for m cyclic replays over n records (mapping draft, section 4.2)."""
    k, q = divmod(m, n)
    return (n + m) ** 2 / ((n - q) * (1 + k) ** 2 + q * (2 + k) ** 2)


def accounting(train: np.ndarray, family: np.ndarray, replay: Replay) -> dict:
    """Distinct rows, replays, nominal rows and Kish ESS, per attack family and for the attack class."""
    labels = family[train].astype(str)
    weights = multiplicities(train, replay.copies)
    out = {"arm": replay.arm, "ratio": replay.ratio, "replay_total": replay.total,
           "requested": replay.requested, "realized": replay.realized, "truncated": replay.truncated,
           "excluded_held_out_events": replay.excluded_held_out, "weights": replay.weights, "families": {}}
    attack = labels != BENIGN
    for f in sorted(set(labels[attack])):
        w = weights[labels == f]
        out["families"][f] = {"distinct": int(len(w)), "replays": int(w.sum() - len(w)),
                              "nominal": int(w.sum()), "ess": kish(w)}
    w = weights[attack]
    out["attack_class"] = {"distinct": int(len(w)), "replays": int(w.sum() - len(w)), "nominal": int(w.sum()),
                           "ess": kish(w)}
    return out
