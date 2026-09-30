"""End-to-end pipeline behaviour for every built-in scenario."""

from __future__ import annotations

import unittest

from soc_agent.models import ActionStatus, ActionType, CaseStatus, Routing, Severity, Verdict

from .helpers import AgentHarness


def statuses(case, action: ActionType) -> list[ActionStatus]:  # noqa: ANN001
    return [a.status for a in case.actions if a.action == action]


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.h = AgentHarness()

    async def asyncTearDown(self) -> None:
        await self.h.close()

    async def test_ransomware_is_contained_and_paged(self) -> None:
        case = await self.h.run("ransomware")
        self.assertEqual(case.verdict, Verdict.TRUE_POSITIVE)
        self.assertEqual(case.severity, Severity.CRITICAL)
        self.assertEqual(case.routing, Routing.PAGE)
        self.assertEqual(case.status, CaseStatus.REMEDIATED)
        isolate = [a for a in case.actions if a.action == ActionType.ISOLATE_DEVICE]
        self.assertEqual(len(isolate), 1, "isolation must not be duplicated between fast path and response")
        self.assertEqual(isolate[0].phase, "fast_path")
        self.assertEqual(statuses(case, ActionType.STOP_AND_QUARANTINE_FILE), [ActionStatus.SUCCESS])
        self.assertIn(ActionStatus.SUCCESS, statuses(case, ActionType.DISABLE_USER))
        blocked = {a.target for a in case.actions if a.action == ActionType.BLOCK_IP}
        self.assertEqual(blocked, {"203.0.113.66", "203.0.113.67"})
        self.assertNotIn("20.190.160.20", blocked, "never-block list must be honoured")
        self.assertTrue(case.sla_met)
        self.assertLess(case.elapsed_seconds, 28)
        world = self.h.agent.connectors.world
        assert world is not None
        self.assertEqual(len(world.isolated), 1)

    async def test_false_positive_auto_released_and_closed(self) -> None:
        case = await self.h.run("false-positive")
        self.assertEqual(case.verdict, Verdict.FALSE_POSITIVE)
        self.assertEqual(case.routing, Routing.AUTO_CLOSE)
        self.assertEqual(case.status, CaseStatus.CLOSED)
        release = [a for a in case.actions if a.action == ActionType.RELEASE_DEVICE]
        self.assertEqual([a.status for a in release], [ActionStatus.SUCCESS])
        world = self.h.agent.connectors.world
        assert world is not None
        self.assertEqual(world.isolated, set(), "device must not stay isolated after a false positive")

    async def test_identity_takeover_contained_in_queue(self) -> None:
        case = await self.h.run("impossible-travel")
        self.assertEqual(case.verdict, Verdict.TRUE_POSITIVE)
        self.assertEqual(case.status, CaseStatus.CONTAINED)
        self.assertEqual(case.routing, Routing.QUEUE)
        self.assertEqual(statuses(case, ActionType.DISABLE_USER), [ActionStatus.SUCCESS])
        flags = " ".join(f for c in case.user_context for f in c.flags)
        self.assertIn("Impossible travel", flags)

    async def test_privileged_account_requires_approval_and_pages(self) -> None:
        case = await self.h.run("privileged-account")
        self.assertEqual(statuses(case, ActionType.DISABLE_USER), [ActionStatus.AWAITING_APPROVAL])
        self.assertEqual(case.status, CaseStatus.AWAITING_APPROVAL)
        self.assertEqual(case.routing, Routing.PAGE)
        action = next(a for a in case.actions if a.action == ActionType.DISABLE_USER)
        approved = await self.h.agent.approve_action(case.id, action.id, "analyst@contoso.com")
        rec = next(a for a in approved.actions if a.id == action.id)
        self.assertEqual(rec.status, ActionStatus.SUCCESS)
        self.assertEqual(rec.approved_by, "analyst@contoso.com")

    async def test_domain_controller_isolation_needs_human(self) -> None:
        case = await self.h.run("domain-controller")
        self.assertEqual(statuses(case, ActionType.ISOLATE_DEVICE), [ActionStatus.AWAITING_APPROVAL])
        self.assertEqual(case.severity, Severity.CRITICAL)
        self.assertEqual(case.routing, Routing.PAGE)

    async def test_unknown_binary_goes_to_queue_with_evidence(self) -> None:
        case = await self.h.run("unknown-binary")
        self.assertEqual(case.verdict, Verdict.UNDETERMINED)
        self.assertEqual(case.routing, Routing.QUEUE)
        self.assertEqual(statuses(case, ActionType.COLLECT_INVESTIGATION_PACKAGE), [ActionStatus.SUCCESS])
        self.assertFalse(any(a.action == ActionType.ISOLATE_DEVICE for a in case.actions))

    async def test_rollback_restores_isolation(self) -> None:
        case = await self.h.run("malware")
        iso = next(a for a in case.actions if a.action == ActionType.ISOLATE_DEVICE)
        updated = await self.h.agent.rollback_action(case.id, iso.id, "analyst@contoso.com")
        self.assertTrue(next(a for a in updated.actions if a.id == iso.id).rolled_back)
        with self.assertRaises(ValueError):
            await self.h.agent.rollback_action(case.id, iso.id, "analyst@contoso.com")

    async def test_duplicate_alert_is_not_reprocessed(self) -> None:
        from soc_agent.normalize import normalize
        from soc_agent.scenarios import SCENARIOS

        source, payload = SCENARIOS["malware"]()
        first = await self.h.agent.handle_alert(normalize(source, payload)[0])
        second = await self.h.agent.handle_alert(normalize(source, payload)[0])
        self.assertEqual(first.id, second.id)

    async def test_failed_containment_escalates_high_to_page(self) -> None:
        world = self.h.agent.connectors.world
        assert world is not None
        world.fail_actions = {"isolate_device"}
        case = await self.h.run("malware")
        self.assertIn(ActionStatus.FAILED, statuses(case, ActionType.ISOLATE_DEVICE))
        self.assertEqual(case.routing, Routing.PAGE)

    async def test_report_contains_key_sections(self) -> None:
        case = await self.h.run("ransomware")
        for section in ("## Summary", "## What the agent did", "## Why (determination)", "## Evidence",
                        "## Recommended next steps", "## Rollback", "## Timeline"):
            self.assertIn(section, case.report_markdown)
        self.assertTrue((self.h.dir / "reports" / f"{case.id}.md").exists())


class DryRunTests(unittest.IsolatedAsyncioTestCase):
    async def test_dry_run_changes_nothing(self) -> None:
        h = AgentHarness(dry_run=True)
        try:
            case = await h.run("ransomware")
            self.assertTrue(case.dry_run)
            effective = {a.status for a in case.actions if a.status not in (ActionStatus.SKIPPED,)}
            self.assertEqual(effective, {ActionStatus.DRY_RUN})
            world = h.agent.connectors.world
            assert world is not None
            self.assertEqual(world.calls, [])
            self.assertIn("DRY RUN", case.report_markdown)
        finally:
            await h.close()


if __name__ == "__main__":
    unittest.main()
