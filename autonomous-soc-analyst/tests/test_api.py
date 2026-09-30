"""API surface: webhook ingestion, auth, case retrieval, approval, admin kill switch."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from soc_agent.api import create_app
from soc_agent.orchestrator import build_agent
from soc_agent.scenarios import SCENARIOS

from .helpers import make_settings


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = make_settings(Path(self.tmp.name), api_key="analyst-key", admin_api_key="admin-key")
        self.agent = build_agent(self.settings)
        self.client = TestClient(create_app(self.settings, self.agent))
        self.client.__enter__()
        self.auth = {"X-API-Key": "analyst-key"}
        self.admin = {"X-Admin-Key": "admin-key"}

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def _submit(self, scenario: str) -> dict:
        source, payload = SCENARIOS[scenario]()
        resp = self.client.post(f"/webhooks/{source}?wait=true", json=payload, headers=self.auth)
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()["cases"][0]

    def test_requires_auth(self) -> None:
        source, payload = SCENARIOS["malware"]()
        self.assertEqual(self.client.post(f"/webhooks/{source}", json=payload).status_code, 401)
        self.assertEqual(self.client.get("/cases").status_code, 401)

    def test_webhook_and_case_retrieval(self) -> None:
        brief = self._submit("ransomware")
        self.assertEqual(brief["verdict"], "true_positive")
        self.assertEqual(brief["routing"], "page")
        case_id = brief["case_id"]
        report = self.client.get(f"/cases/{case_id}/report", headers=self.auth)
        self.assertEqual(report.status_code, 200)
        self.assertIn("Incident Report", report.text)
        listing = self.client.get("/cases", headers=self.auth).json()["cases"]
        self.assertTrue(any(c["id"] == case_id for c in listing))

    def test_approval_flow(self) -> None:
        brief = self._submit("privileged-account")
        pending = next(a for a in brief["actions"] if a["status"] == "awaiting_approval")
        resp = self.client.post(f"/cases/{brief['case_id']}/actions/{pending['id']}/approve",
                                json={"approver": "analyst@contoso.com"}, headers=self.auth)
        self.assertEqual(resp.status_code, 200, resp.text)
        approved = next(a for a in resp.json()["actions"] if a["id"] == pending["id"])
        self.assertEqual(approved["status"], "success")

    def test_approval_requires_who(self) -> None:
        brief = self._submit("privileged-account")
        pending = next(a for a in brief["actions"] if a["status"] == "awaiting_approval")
        resp = self.client.post(f"/cases/{brief['case_id']}/actions/{pending['id']}/approve",
                                json={}, headers=self.auth)
        self.assertEqual(resp.status_code, 400)

    def test_admin_kill_blocks_processing_and_needs_admin_key(self) -> None:
        self.assertEqual(self.client.post("/admin/kill", json={"level": "full"}, headers=self.auth).status_code, 401)
        resp = self.client.post("/admin/kill", json={"level": "full", "reason": "drill", "engaged_by": "me"},
                                headers=self.admin)
        self.assertEqual(resp.status_code, 200)
        source, payload = SCENARIOS["malware"]()
        held = self.client.post(f"/webhooks/{source}", json=payload, headers=self.auth)
        self.assertEqual(held.status_code, 503)
        self.assertEqual(self.client.get("/health").json()["status"], "halted")

    def test_admin_audit_endpoint(self) -> None:
        self._submit("malware")
        resp = self.client.get("/admin/audit", headers=self.admin)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["chain_ok"])
        self.assertGreater(body["entries"], 0)

    def test_no_resume_endpoint(self) -> None:
        # Clearing the kill switch is deliberately not exposed over the API: it requires
        # shell access to the host. Any /admin/resume route must simply not exist.
        resp = self.client.post("/admin/resume", json={}, headers=self.admin)
        self.assertEqual(resp.status_code, 404)


class LiveConfigGuardTests(unittest.TestCase):
    def test_live_mode_requires_distinct_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            s = make_settings(Path(tmp), mock_mode=False, api_key="same", admin_api_key="same")
            with self.assertRaises(RuntimeError):
                create_app(s)


if __name__ == "__main__":
    unittest.main()
