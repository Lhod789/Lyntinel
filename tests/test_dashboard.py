"""Guards on the dashboard's provenance labelling and layout.

The dashboard is static HTML with no test runner behind it, so these are
source-level assertions rather than DOM tests.

The rule being enforced: this page renders canned data, so every source reads
SIM and nothing on the page suggests otherwise. A chip or caption implying
real data would be exactly the false provenance claim the evidence labels
exist to prevent.
"""

import re
import unittest
from pathlib import Path

DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard" / "dashboard.html"


class TestDashboardProvenance(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = DASHBOARD.read_text(encoding="utf-8")

    def test_dashboard_exists(self):
        self.assertTrue(DASHBOARD.exists())

    def test_every_chip_is_tagged_sim(self):
        renderer = self._renderer_block()
        self.assertIn("SIM", renderer)
        self.assertNotIn(">LIVE<", self.html)

    def test_nothing_on_the_page_implies_real_data(self):
        """The page once carried a per-source flag and a caption explaining
        which sources could be pulled from a real API. On a page of canned
        data that was one claim too many, so none of it may come back."""
        lowered = self.html.lower()
        for phrase in ("liveapi", "real free api", "credentials are set", "live agent"):
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, lowered)

    def test_caption_says_the_page_is_canned_data(self):
        self.assertIn("canned data", self.html.lower())

    def _renderer_block(self):
        match = re.search(r'getElementById\("conn"\)\.innerHTML(.*?)join\(""\);',
                          self.html, re.DOTALL)
        self.assertIsNotNone(match, "connector chip renderer not found")
        return match.group(1)


class TestDashboardLayout(unittest.TestCase):

    def test_chat_panel_takes_only_the_space_left_over(self):
        """The chat panel used to claim height:100% of the right-hand column.
        That squeezed the Finding intelligence panel, whose overflow is hidden,
        until its score total, remediation and the button that opens the
        approval gate were clipped out of reach. The chat must fill what is
        left over, not take the whole column."""
        html = DASHBOARD.read_text(encoding="utf-8")
        rule = re.search(r"\.chat\{([^}]*)\}", html)
        self.assertIsNotNone(rule, ".chat style is missing")
        body = rule.group(1).replace(" ", "")
        self.assertNotIn("height:100%", body)
        self.assertIn("flex:1", body)


class TestDashboardNaming(unittest.TestCase):

    def test_dashboard_uses_the_project_name(self):
        html = DASHBOARD.read_text(encoding="utf-8")
        self.assertIn("Lyntinel", html)


if __name__ == "__main__":
    unittest.main()
