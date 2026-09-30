"""Normalisation, triage scoring, intel consensus and utility correctness."""

from __future__ import annotations

import unittest

from soc_agent.intel import aggregate
from soc_agent.models import IntelVerdict, ProviderResult, Severity
from soc_agent.normalize import NormalizationError, normalize
from soc_agent.scenarios import SCENARIOS
from soc_agent.utils import Deadline, is_public_ip, normalize_hash, parse_ip


class NormalizeTests(unittest.TestCase):
    def test_every_scenario_normalizes(self) -> None:
        for name, fn in SCENARIOS.items():
            source, payload = fn()
            alerts = normalize(source, payload)
            self.assertEqual(len(alerts), 1, name)
            alert = alerts[0]
            self.assertTrue(alert.id and alert.title, name)
            self.assertTrue(alert.devices or alert.users or alert.files, name)

    def test_defender_graph_entities(self) -> None:
        alert = normalize(*SCENARIOS["ransomware"]())[0]
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.devices[0].hostname, "ws-fin-042.contoso.com")
        self.assertTrue(alert.files[0].sha256)
        self.assertIn("T1486", alert.mitre_techniques)

    def test_graph_next_link_host_restaint(self) -> None:
        # unknown source is rejected
        with self.assertRaises(NormalizationError):
            normalize("nessus", {"title": "x"})

    def test_generic_requires_title(self) -> None:
        with self.assertRaises(NormalizationError):
            normalize("generic", {"severity": "high"})

    def test_batch_and_value_wrapper(self) -> None:
        _, payload = SCENARIOS["malware"]()
        self.assertEqual(len(normalize("defender", [payload, payload])), 2)
        self.assertEqual(len(normalize("defender", {"value": [payload]})), 1)


class HashIpTests(unittest.TestCase):
    def test_hash_detection(self) -> None:
        self.assertEqual(normalize_hash("A" * 64), ("sha256", "a" * 64))
        self.assertEqual(normalize_hash("b" * 40), ("sha1", "b" * 40))
        self.assertIsNone(normalize_hash("xyz"))

    def test_ip_parsing_and_scope(self) -> None:
        self.assertEqual(parse_ip("203.0.113.5:443"), "203.0.113.5")
        self.assertIsNone(parse_ip("not-an-ip"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("203.0.113.5"))  # documentation range, off by default
        self.assertTrue(is_public_ip("203.0.113.5", allow_documentation=True))
        self.assertTrue(is_public_ip("8.8.8.8"))


class AggregateTests(unittest.TestCase):
    def _r(self, verdict: IntelVerdict, score: int = 0) -> ProviderResult:
        return ProviderResult(provider="p", indicator="x", indicator_type="hash", verdict=verdict, score=score,
                              found=True)

    def test_consensus_needs_min_sources(self) -> None:
        one = aggregate("x", "hash", [self._r(IntelVerdict.MALICIOUS, 60), self._r(IntelVerdict.UNKNOWN)], 2)
        self.assertEqual(one.verdict, IntelVerdict.SUSPICIOUS)
        two = aggregate("x", "hash", [self._r(IntelVerdict.MALICIOUS, 60), self._r(IntelVerdict.MALICIOUS, 55)], 2)
        self.assertEqual(two.verdict, IntelVerdict.MALICIOUS)

    def test_single_high_confidence_source_is_enough(self) -> None:
        result = aggregate("x", "hash", [self._r(IntelVerdict.MALICIOUS, 95)], 2)
        self.assertEqual(result.verdict, IntelVerdict.MALICIOUS)

    def test_benign_when_only_benign(self) -> None:
        result = aggregate("x", "hash", [self._r(IntelVerdict.BENIGN), self._r(IntelVerdict.BENIGN)], 2)
        self.assertEqual(result.verdict, IntelVerdict.BENIGN)


class DeadlineTests(unittest.TestCase):
    def test_budget_reserves_time(self) -> None:
        d = Deadline(28)
        self.assertLessEqual(d.budget(reserve=20, cap=100), 8.01)
        self.assertEqual(d.budget(reserve=30, cap=100), 0.0)
        self.assertLessEqual(d.budget(reserve=0, cap=5), 5.0)


if __name__ == "__main__":
    unittest.main()
