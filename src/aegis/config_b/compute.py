"""Measured-CPU accounting and the stop rules (section 12).

CPU is the process's own user plus system time (``RUSAGE_SELF``, which includes the forest's threads) plus
``RUSAGE_CHILDREN`` for any joined child process. The bank's 3.24 CPU-h counts as already spent.
"""

from __future__ import annotations

import csv
import os
import resource
import time
from contextlib import contextmanager
from pathlib import Path

from aegis.config_b import protocol


class StopRun(RuntimeError):
    """A stop rule fired. The run stops at a fit or stage boundary and reports."""


def cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def live_children() -> list[int]:
    """Process ids whose parent is this process (Linux ``/proc``)."""
    me, found = os.getpid(), []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if int(fields[1]) == me:
            found.append(int(entry.name))
    return found


class Ledger:
    """One row per fit in ``compute_ledger.csv``: stage, label, measured CPU seconds and wall seconds."""

    FIELDS = ("stage", "label", "cpu_seconds", "wall_seconds", "finished_utc")

    def __init__(self, path: Path, approved_budget: float = protocol.APPROVED_PLANNING_BUDGET,
                 past_planning_ceiling: bool = False) -> None:
        self.path = path
        self.approved_budget = approved_budget
        self.past_planning_ceiling = past_planning_ceiling  # Only an explicit owner authorization sets this.
        self.rows: list[dict] = []
        if path.exists():
            with open(path, newline="", encoding="utf-8") as handle:
                self.rows = [dict(r, cpu_seconds=float(r["cpu_seconds"]), wall_seconds=float(r["wall_seconds"]))
                             for r in csv.DictReader(handle)]

    def measured_hours(self, stage: str | None = None) -> float:
        rows = self.rows if stage is None else [r for r in self.rows if r["stage"] == stage]
        return sum(r["cpu_seconds"] for r in rows) / 3600

    def total_hours(self) -> float:
        return protocol.STAGE0_SPENT_CPU_HOURS + self.measured_hours()

    def stages_done(self) -> list[str]:
        return [s for s in protocol.STAGES if any(r["stage"] == s for r in self.rows)]

    def ratio(self, finished: list[str]) -> float:
        """Measured CPU over the ceiling for the finished stages; 1.0 before any stage has finished."""
        ceiling = sum(protocol.STAGE_CEILINGS[s] for s in finished)
        return self.measured_hours_of(finished) / ceiling if ceiling else 1.0

    def measured_hours_of(self, stages: list[str]) -> float:
        return sum(self.measured_hours(s) for s in stages)

    def projection(self, stage: str, finished: list[str]) -> dict:
        remaining = [s for s in protocol.STAGES if s not in finished and protocol.STAGES.index(s) >= protocol.STAGES.index(stage)]
        ratio = self.ratio(finished)
        estimates = {s: protocol.STAGE_CEILINGS[s] * ratio for s in remaining}
        return {
            "stage": stage, "measured_total": self.total_hours(),
            "measured_by_stage": {"0": protocol.STAGE0_SPENT_CPU_HOURS,
                                  **{s: self.measured_hours(s) for s in protocol.STAGES}},
            "ratio_measured_to_ceiling": ratio, "remaining_estimates": estimates,
            "projected_total": self.total_hours() + sum(estimates.values()),
            "approved_budget": self.approved_budget,
        }

    def before_stage(self, stage: str, finished: list[str]) -> dict:
        """Stop rules 1, 2 and 4, applied before ``stage`` starts. Returns the projection when it may start."""
        p = self.projection(stage, finished)
        if p["projected_total"] > protocol.HARD_STOP:
            raise StopRun(f"stop before stage {stage}: projection {p['projected_total']:.1f} exceeds the hard stop "
                          f"{protocol.HARD_STOP:.0f} CPU-h. {p}")
        if p["projected_total"] > protocol.PLANNING_CEILING and not self.past_planning_ceiling:
            raise StopRun(f"stop before stage {stage}: projection {p['projected_total']:.1f} exceeds "
                          f"{protocol.PLANNING_CEILING:.0f} CPU-h, a hard limit without explicit owner authorization. {p}")
        if p["projected_total"] > self.approved_budget:
            raise StopRun(f"stop before stage {stage}: projection {p['projected_total']:.1f} exceeds the approved "
                          f"planning budget {self.approved_budget} CPU-h. Owner approval needed with the measured "
                          f"consumption, remaining estimates, reason and proposed changes. {p}")
        return p

    @contextmanager
    def fit(self, stage: str, label: str):
        """Measure one fit. After it, at 175 measured CPU-h, stop at this fit boundary (rule 3)."""
        if self.total_hours() >= protocol.IN_STAGE_STOP:
            raise StopRun(f"measured CPU {self.total_hours():.2f} h has reached {protocol.IN_STAGE_STOP:.0f}")
        cpu, wall = cpu_seconds(), time.perf_counter()
        try:
            yield
        finally:  # A fit that fails still spent CPU, so it is recorded too.
            row = {"stage": stage, "label": label, "cpu_seconds": cpu_seconds() - cpu,
                   "wall_seconds": time.perf_counter() - wall,
                   "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            self.rows.append(row)
            new = not self.path.exists()
            with open(self.path, "a", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=self.FIELDS)
                if new:
                    writer.writeheader()
                writer.writerow(row)
        if self.total_hours() >= protocol.IN_STAGE_STOP:
            raise StopRun(f"measured CPU {self.total_hours():.2f} h reached {protocol.IN_STAGE_STOP:.0f}; "
                          f"stopped at the fit boundary after {label}")

    def end_stage(self, stage: str) -> None:
        children = live_children()
        if children:
            raise StopRun(f"stage {stage} ended with live child processes {children}; their CPU would go unrecorded")
