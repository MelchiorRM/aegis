"""CAGE Challenge 4 feasibility probe for the Config B spike. Feasibility code only.

It runs CybORG episodes and logs, step by step, every agent's executed action (type, target parameters, outcome),
a summary of the blue agents' observations (host-level events, the simulated telemetry), and the rewards. It
loads no dataset, fits no model, and generates no Config B training data.

Run with the isolated spike environment, not the Aegis one:
    ~/aegis-spike/venv/bin/python spikes/cage4/probe.py --seed 0 --steps 500 --blue sleep --out run.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
import warnings

warnings.filterwarnings("ignore")  # gym 0.26.2 prints an "unmaintained" notice on import.

from CybORG import CybORG, CYBORG_VERSION  # noqa: E402
from CybORG.Agents import EnterpriseGreenAgent, FiniteStateRedAgent, SleepAgent  # noqa: E402
from CybORG.Simulator.Actions import Monitor, Restore, Sleep  # noqa: E402
from CybORG.Simulator.Scenarios import EnterpriseScenarioGenerator  # noqa: E402

TARGET_FIELDS = ("hostname", "ip_address", "subnet", "session", "target_session")


def describe(action) -> dict:
    """An action as plain data: its type and its target parameters."""
    fields = getattr(action, "__dict__", {})
    described = {"type": type(action).__name__, **{k: str(fields[k]) for k in TARGET_FIELDS if k in fields}}
    if fields.get("sub_action") is not None:  # ExploitRemoteService records the concrete exploit it chose.
        described["sub_action"] = type(fields["sub_action"]).__name__
    return described


def blue_events(observation: dict) -> list[str]:
    """Hosts the blue agent's observation reports something about (alerts or analysis results)."""
    return sorted(k for k, v in observation.items() if k not in ("success", "action", "message") and isinstance(v, dict))


def episode(seed: int, steps: int, blue_policy: str) -> tuple[list[dict], float]:
    generator = EnterpriseScenarioGenerator(
        blue_agent_class=SleepAgent, green_agent_class=EnterpriseGreenAgent,
        red_agent_class=FiniteStateRedAgent, steps=steps,
    )
    env = CybORG(generator, "sim", seed=seed)
    blue = sorted(a for a in env.agents if a.startswith("blue"))
    records = []
    flagged: dict[str, list[str]] = {b: [] for b in blue}
    started = time.perf_counter()
    for step in range(steps):
        # Blue is externally controlled. Each policy is a fixed script, not a learner. Monitor also runs
        # automatically every step in CAGE 4, so "monitor" leaves the world unchanged; "restore" changes it.
        if blue_policy == "monitor":
            actions = {b: Monitor(session=0, agent=b) for b in blue}
        elif blue_policy == "restore":
            actions = {b: Restore(session=0, agent=b, hostname=flagged[b][0]) if flagged[b] else Sleep() for b in blue}
        else:
            actions = {b: Sleep() for b in blue}
        observations, rewards, done, _ = env.parallel_step(actions)
        record = {"step": step, "red": {}, "green_actions": {}, "blue": {}, "rewards": {}}
        for agent in sorted(env.active_agents):
            acted = env.get_last_action(agent)
            acted = [describe(a) for a in (acted if isinstance(acted, list) else [acted]) if a is not None]
            outcome = str(env.get_observation(agent).get("success"))
            if agent.startswith("red"):
                record["red"][agent] = {"actions": acted, "success": outcome}
            elif agent.startswith("green"):
                kinds = [a["type"] for a in acted if a["type"] != "Sleep"]
                for kind in kinds:
                    record["green_actions"][kind] = record["green_actions"].get(kind, 0) + 1
        for agent in blue:
            record["blue"][agent] = {"actions": [describe(a) for a in env.get_last_action(agent)],
                                     "event_hosts": blue_events(observations.get(agent, {}))}
            flagged[agent] = record["blue"][agent]["event_hosts"]
            record["rewards"][agent] = {k: float(v) for k, v in sorted(rewards.get(agent, {}).items())}
        records.append(record)
        if any(done.values()):
            break
    return records, time.perf_counter() - started


def digest(records: list[dict]) -> str:
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--steps", type=int, default=500)
    parser.add_argument("--blue", choices=("sleep", "monitor", "restore"), default="sleep")
    parser.add_argument("--out")
    args = parser.parse_args()
    records, seconds = episode(args.seed, args.steps, args.blue)
    summary = {
        "seed": args.seed, "steps": len(records), "blue": args.blue, "seconds": round(seconds, 3),
        "steps_per_second": round(len(records) / seconds, 2), "trajectory_sha256": digest(records),
        "cyborg_version": CYBORG_VERSION, "python": platform.python_version(),
        "red_actions": sum(1 for r in records for v in r["red"].values() for a in v["actions"] if a["type"] != "Sleep"),
        "blue_event_hosts": sum(len(v["event_hosts"]) for r in records for v in r["blue"].values()),
        "red_successes": sum(1 for r in records for v in r["red"].values() if v["success"] == "TRUE"),
        "blue_reward_total": round(sum(sum(v.values()) for r in records for v in r["rewards"].values()), 3),
        "blue_non_sleep_actions": sum(1 for r in records for v in r["blue"].values() for a in v["actions"] if a["type"] != "Sleep"),
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
    json.dump(summary, sys.stdout)
    print()


if __name__ == "__main__":
    main()
