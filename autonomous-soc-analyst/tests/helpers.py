"""Shared test helpers: an isolated agent against the simulated tenant."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from soc_agent.config import Settings
from soc_agent.normalize import normalize
from soc_agent.orchestrator import SOCAgent, build_agent
from soc_agent.scenarios import SCENARIOS

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)


def make_settings(workdir: Path, **overrides: object) -> Settings:
    base = dict(
        mock_mode=True, db_path=":memory:", data_dir=str(workdir), reports_dir=str(workdir / "reports"),
        kill_switch_file=str(workdir / "KILL_SWITCH"), audit_log_path=str(workdir / "audit.jsonl"),
        safety_state_path=str(workdir / "state.json"), integrity_manifest_path=str(workdir / "integrity.lock"),
        mock_latency_scale=0.0, policy_path=str(ROOT / "ir_policy.yaml"),
        safety_policy_path=str(ROOT / "safety.yaml"),
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


class AgentHarness:
    def __init__(self, **overrides: object) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="soc-test-")
        self.dir = Path(self._tmp.name)
        self.settings = make_settings(self.dir, **overrides)
        self.agent: SOCAgent = build_agent(self.settings)

    async def run(self, scenario: str):  # noqa: ANN201
        source, payload = SCENARIOS[scenario]()
        return await self.agent.handle_alert(normalize(source, payload)[0])

    async def close(self) -> None:
        await self.agent.safety.monitor.flush()
        await self.agent.aclose()
        self._tmp.cleanup()
