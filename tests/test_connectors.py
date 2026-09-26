"""Tests for the connector layer and the mock payloads behind it.

Two things must hold. First, every source says it is simulated: no result may
ever present mock data as real. Second, the mock files keep the shape the
scenarios parse, so a rename or a reshaped payload fails here rather than in a
demo.
"""

import json
import unittest
from pathlib import Path

from scenarios.appsec import connectors

MOCK_DIR = connectors.MOCK_DIR

SOURCES = ("fetch_threat_model", "fetch_appsec_findings", "fetch_asset_inventory",
           "fetch_accepted_risks", "fetch_tickets", "fetch_exploit_intel")


class TestSimulatedSources(unittest.TestCase):

    def test_no_source_claims_to_be_live(self):
        for name in SOURCES:
            with self.subTest(source=name):
                self.assertFalse(getattr(connectors, name)().live)

    def test_every_source_says_it_is_simulated(self):
        """A watcher has to be able to tell simulated data at a glance."""
        for name in SOURCES:
            with self.subTest(source=name):
                self.assertIn("SIMULATED", getattr(connectors, name)().detail.upper())

    def test_every_source_returns_data_and_a_note(self):
        for name in SOURCES:
            with self.subTest(source=name):
                result = getattr(connectors, name)()
                self.assertTrue(result.data, "a source must return data")
                self.assertTrue(result.detail.strip())

    def test_sources_cannot_reach_the_network(self):
        """The demo is offline by design. A connector module that imported
        the means to make a network call would break that promise, whether
        or not the call ever ran."""
        source = Path(connectors.__file__).read_text(encoding="utf-8")
        for token in ("urllib", "http.client", "socket", "requests"):
            with self.subTest(token=token):
                self.assertNotIn(token, source)


class TestMockPayloadShapes(unittest.TestCase):
    """These pin the filenames and top-level keys the scenarios depend on.
    The mock files were renamed during sanitisation; this is what catches a
    rename that misses a reference."""

    EXPECTED = {
        "appsec_findings.json": "issues",
        "asset_inventory.json": "assets",
        "grc_risks.json": "accepted_risks",
        "tickets.json": "issues",
        "exploit_intel.json": "known_exploited",
        "awareness_profiles.json": "users",
        "email_security_events.json": "messages",
        "scan_history.json": None,
        "edr_alert.json": None,
    }

    def test_expected_mock_files_exist(self):
        for name in self.EXPECTED:
            with self.subTest(name=name):
                self.assertTrue((MOCK_DIR / name).exists(), f"{name} is missing")

    def test_mock_files_are_valid_json_with_the_expected_root_key(self):
        for name, key in self.EXPECTED.items():
            with self.subTest(name=name):
                data = json.loads((MOCK_DIR / name).read_text(encoding="utf-8"))
                if key is not None:
                    self.assertIn(key, data)

    def test_every_mock_payload_is_labelled_simulated(self):
        """Loud provenance: mock data must announce itself inside the file, so
        it cannot be mistaken for real data by anyone reading the repo."""
        for name in self.EXPECTED:
            with self.subTest(name=name):
                data = json.loads((MOCK_DIR / name).read_text(encoding="utf-8"))
                self.assertIn("_SIMULATED", data,
                              f"{name} must carry a _SIMULATED label")
                self.assertTrue(str(data["_SIMULATED"]).strip())

    def test_email_events_expose_the_fields_the_correlation_joins_on(self):
        data = json.loads((MOCK_DIR / "email_security_events.json").read_text(encoding="utf-8"))
        click = data["url_clicks"][0]
        for key in ("recipient", "url", "click_time"):
            with self.subTest(key=key):
                self.assertIn(key, click)

    def test_edr_alert_exposes_the_fields_the_correlation_reads(self):
        data = json.loads((MOCK_DIR / "edr_alert.json").read_text(encoding="utf-8"))
        self.assertIn("device", data)
        for key in ("user", "hostname"):
            with self.subTest(key=key):
                self.assertIn(key, data["device"])
        for key in ("technique", "technique_id", "severity_label"):
            with self.subTest(key=key):
                self.assertIn(key, data)

    def test_awareness_profiles_expose_the_risk_level(self):
        data = json.loads((MOCK_DIR / "awareness_profiles.json").read_text(encoding="utf-8"))
        self.assertTrue(data["users"])
        for user in data["users"]:
            with self.subTest(user=user.get("email")):
                self.assertIn("awareness_risk_level", user)


if __name__ == "__main__":
    unittest.main()
