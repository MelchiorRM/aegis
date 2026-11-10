"""Outcome counting (rules O1-O6) and the pre-run check of the reused scenario bank (sections 4 and 5).

Nothing here runs a simulator. The bank's logs are read only.
"""

from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path

from aegis.config_b import protocol


class BankMismatch(RuntimeError):
    """The bank on disk is not the registered bank. The run stops."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def count_actions(lines) -> collections.Counter:
    """Count one episode's red actions under rules O1-O6.

    Keys:
    - ``("attempt", type, sub)``: O2 and O3, each executed action once;
    - ``("success", type, sub)``: O2 only;
    - ``("O1", type, sub)``: a non-Sleep action still in progress (CAGE logs in-progress ticks as Sleep, so this
      is expected to stay zero);
    - ``("O4",)``: an exploit that failed before choosing any service;
    - ``("O6", type, sub)``: outcome UNKNOWN;
    - ``("mapped", family)``: the mapped attempts.

    ``Sleep`` is never counted, whatever its outcome.
    """
    counts: collections.Counter = collections.Counter()
    for line in lines:
        step = json.loads(line) if isinstance(line, (str, bytes)) else line
        for red in step["red"].values():
            outcome = red["success"]
            for action in red["actions"]:
                kind, sub = action["type"], action.get("sub_action", "")
                if kind == "Sleep":
                    continue
                if outcome == "IN_PROGRESS":
                    counts[("O1", kind, sub)] += 1
                    continue
                if outcome == "UNKNOWN":
                    counts[("O6", kind, sub)] += 1
                    continue
                if kind == "ExploitRemoteService" and not sub:
                    counts[("O4",)] += 1
                    continue
                counts[("attempt", kind, sub)] += 1
                if outcome == "TRUE":
                    counts[("success", kind, sub)] += 1
                family = protocol.MAPPING.get((kind, sub if kind == "ExploitRemoteService" else ""))
                if family is not None:
                    counts[("mapped", family)] += 1
    return counts


def verify_bank(bank_dir: Path = protocol.DEFAULT_BANK_DIR, manifest_path: Path = protocol.BANK_MANIFEST) -> dict:
    """The pre-run check (section 4). Every check must pass, or ``BankMismatch`` stops the run.

    It checks:
    - the manifest's sha256;
    - the seed rule;
    - every log's sha256;
    - every summary's seed, steps and blue policy;
    - every episode's mapped counts, recomputed under O1-O6;
    - every fold seed's totals.

    It returns the per-fold-seed event counts and the outcome report.
    """
    if sha256(manifest_path) != protocol.BANK_MANIFEST_SHA256:
        raise BankMismatch(f"{manifest_path} is not the registered manifest (sha256 differs)")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {(e["fold_seed"], e["episode"]): e for e in manifest["episodes"]}
    seeds = protocol.bank_seeds()
    if set(expected) != {(f, e) for f, e, _ in seeds}:
        raise BankMismatch("the manifest's episodes are not 50 per fold seed for fold seeds 0-4")
    if len({s for _, _, s in seeds}) != len(seeds):
        raise BankMismatch("simulator seeds are not unique")

    per_seed = {f: collections.Counter() for f in protocol.FOLD_SEEDS}
    for fold_seed, episode, seed in seeds:
        entry = expected[(fold_seed, episode)]
        if entry["sim_seed"] != seed:
            raise BankMismatch(f"episode ({fold_seed}, {episode}): seed {entry['sim_seed']} breaks the seed rule")
        log = bank_dir / f"seed_{seed:04d}.jsonl"
        if sha256(log) != entry["log_sha256"]:
            raise BankMismatch(f"{log.name}: sha256 differs from the manifest")
        summary = json.loads((bank_dir / f"seed_{seed:04d}.summary.json").read_text(encoding="utf-8"))
        if (summary["seed"], summary["steps"], summary["blue"]) != (seed, protocol.BANK_STEPS, protocol.BANK_BLUE):
            raise BankMismatch(f"{log.name}: the summary does not match the bank configuration")
        with open(log, encoding="utf-8") as handle:
            counts = count_actions(handle)
        for family in protocol.MAPPED_FAMILIES:
            if counts[("mapped", family)] != entry[f"mapped_{family}"]:
                raise BankMismatch(f"{log.name}: {family} {counts[('mapped', family)]} recomputed, "
                                   f"{entry[f'mapped_{family}']} in the manifest")
        per_seed[fold_seed].update(counts)

    events, report = {}, {}
    for fold_seed, counts in per_seed.items():
        recorded = manifest["per_fold_seed"][str(fold_seed)]
        events[fold_seed] = {f: counts[("mapped", f)] for f in protocol.MAPPED_FAMILIES}
        for family in protocol.MAPPED_FAMILIES:
            if events[fold_seed][family] != recorded[family]:
                raise BankMismatch(f"fold seed {fold_seed} {family}: totals differ from the manifest")
        attempts = sum(n for k, n in counts.items() if k[0] == "attempt")
        report[fold_seed] = {
            "mapped": events[fold_seed],
            "attempts": attempts,
            "unmapped_attempts": attempts - sum(events[fold_seed].values()),
            "O1_in_progress_non_sleep": sum(n for k, n in counts.items() if k[0] == "O1"),
            "O4_unreachable_exploits": counts[("O4",)],
            "O6_unknown_non_sleep": sum(n for k, n in counts.items() if k[0] == "O6"),
        }
    return {"events": events, "report": report, "manifest_sha256": protocol.BANK_MANIFEST_SHA256}
