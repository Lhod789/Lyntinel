"""Tests for business-aware scoring.

The claim is "P1-P4 by business impact, not raw CVSS". These tests pin the
two claims that makes: that context actually moves the number, and that the
move is always attributable to a sourced adjustment.
"""

import unittest

from core.scoring import score_finding


class TestBaseSeverity(unittest.TestCase):

    def test_each_severity_has_a_distinct_base(self):
        bare = {}
        scores = {sev: score_finding(sev, bare).score
                  for sev in ("critical", "high", "medium", "low")}
        self.assertEqual(scores, {"critical": 40, "high": 30, "medium": 15, "low": 5})

    def test_severity_is_case_insensitive(self):
        self.assertEqual(score_finding("CRITICAL", {}).score,
                         score_finding("critical", {}).score)

    def test_unrecognised_severity_falls_back_without_raising(self):
        result = score_finding("catastrophic", {})
        self.assertEqual(result.score, 15)

    def test_missing_severity_is_treated_as_unknown(self):
        for value in (None, ""):
            with self.subTest(value=value):
                self.assertEqual(score_finding(value, {}).score, 15)


class TestAbsenceOfEvidence(unittest.TestCase):
    """The documented contract: a question we cannot answer must not move the
    score. Absence of evidence is not a downgrade - nor an upgrade."""

    def test_empty_context_applies_no_adjustments(self):
        result = score_finding("high", {})
        self.assertEqual(result.score, 30)
        self.assertEqual(result.adjustments, [])

    def test_none_values_are_not_treated_as_false(self):
        """`internet_facing: None` means unknown. Only an explicit False may
        earn the internal-only discount."""
        unknown = score_finding("high", {"internet_facing": None})
        self.assertEqual(unknown.adjustments, [])

        known_internal = score_finding("high", {"internet_facing": False})
        self.assertEqual(known_internal.score, 20)


class TestAdjustments(unittest.TestCase):

    def test_internet_facing_raises_and_internal_lowers(self):
        self.assertEqual(score_finding("high", {"internet_facing": True}).score, 50)
        self.assertEqual(score_finding("high", {"internet_facing": False}).score, 20)

    def test_active_exploit_raises(self):
        self.assertEqual(score_finding("high", {"active_exploit": True}).score, 55)

    def test_unreachable_code_lowers(self):
        self.assertEqual(score_finding("high", {"reachable": False}).score, 5)

    def test_undeployed_component_lowers(self):
        self.assertEqual(score_finding("high", {"deployed": False}).score, 10)

    def test_unreachable_takes_precedence_over_undeployed(self):
        """These are deliberately exclusive: an unreachable code path already
        implies the finding is not live, so stacking both would double-count."""
        result = score_finding("high", {"reachable": False, "deployed": False})
        self.assertEqual(result.score, 5)
        self.assertEqual(len(result.adjustments), 1)

    def test_sensitive_data_raises_for_each_recognised_tag(self):
        for tag in ("PII", "PHI", "PCI", "PII+PCI"):
            with self.subTest(tag=tag):
                self.assertEqual(score_finding("high", {"data_classification": tag}).score, 50)

    def test_unclassified_data_does_not_move_the_score(self):
        for value in ("public", "", None):
            with self.subTest(value=value):
                self.assertEqual(score_finding("high", {"data_classification": value}).score, 30)

    def test_regulatory_scope_raises_and_empty_scope_does_not(self):
        self.assertEqual(score_finding("high", {"regulatory_scope": ["PCI-DSS"]}).score, 40)
        self.assertEqual(score_finding("high", {"regulatory_scope": []}).score, 30)

    def test_asset_tier_raises_proportionally(self):
        tier1 = score_finding("high", {"asset_criticality": "tier1"}).score
        tier2 = score_finding("high", {"asset_criticality": "tier2"}).score
        tier3 = score_finding("high", {"asset_criticality": "tier3"}).score
        self.assertEqual((tier1, tier2, tier3), (45, 38, 30))
        self.assertGreater(tier1, tier2)

    def test_compensating_control_lowers(self):
        self.assertEqual(score_finding("high", {"control_covers": True}).score, 15)

    def test_accepted_risk_lowers_and_is_flagged(self):
        result = score_finding("high", {"accepted_risk": True})
        self.assertEqual(result.score, 0)
        self.assertTrue(result.accepted_risk)

    def test_accepted_risk_flag_is_false_by_default(self):
        self.assertFalse(score_finding("high", {}).accepted_risk)


class TestScoreFloor(unittest.TestCase):

    def test_score_never_goes_negative(self):
        result = score_finding("low", {
            "internet_facing": False, "reachable": False,
            "control_covers": True, "accepted_risk": True,
        })
        self.assertEqual(result.score, 0)
        self.assertEqual(result.priority, "P4")

    def test_floor_does_not_erase_the_working(self):
        """Clamping the total must not hide which adjustments were applied -
        the audit trail is the point."""
        result = score_finding("low", {"accepted_risk": True, "control_covers": True})
        self.assertEqual(result.score, 0)
        self.assertEqual(len(result.adjustments), 2)


class TestPriorityBands(unittest.TestCase):
    """Band edges are where an off-by-one silently mis-prioritises a finding,
    so each boundary is pinned from both sides."""

    def test_band_boundaries(self):
        cases = [
            (80, "P1"), (79, "P2"),
            (60, "P2"), (59, "P3"),
            (35, "P3"), (34, "P4"),
            (0, "P4"),
        ]
        for target, expected in cases:
            with self.subTest(score=target):
                self.assertEqual(_priority_at(target), expected)

    def test_labels_track_priorities(self):
        self.assertEqual(_result_at(80).business_severity, "Critical")
        self.assertEqual(_result_at(60).business_severity, "High")
        self.assertEqual(_result_at(35).business_severity, "Medium")
        self.assertEqual(_result_at(0).business_severity, "Low")


def _result_at(target):
    """Build a result landing on an exact score, so band edges can be tested
    without depending on any particular combination of context flags."""
    from core.scoring import _band, ScoreResult
    label, priority = _band(target)
    return ScoreResult(technical_severity="unknown", business_severity=label,
                       priority=priority, score=target)


def _priority_at(target):
    return _result_at(target).priority


class TestTransparency(unittest.TestCase):
    """Every movement must be attributable. A number nobody can audit is the
    black box this scorer exists to avoid."""

    def test_each_adjustment_carries_reason_and_source(self):
        result = score_finding("critical", {
            "internet_facing": True, "data_classification": "PII+PCI",
            "regulatory_scope": ["PCI-DSS"], "asset_criticality": "tier1",
            "control_covers": True,
        })
        self.assertTrue(result.adjustments)
        for adjustment in result.adjustments:
            with self.subTest(reason=adjustment.reason):
                self.assertTrue(adjustment.reason.strip(), "adjustment needs a reason")
                self.assertTrue(adjustment.source.strip(), "adjustment needs a source")
                self.assertNotEqual(adjustment.delta, 0, "a no-op adjustment is noise")

    def test_adjustments_sum_to_the_final_score(self):
        context = {"internet_facing": True, "active_exploit": True,
                   "data_classification": "PII", "asset_criticality": "tier1"}
        result = score_finding("high", context)
        self.assertEqual(30 + sum(a.delta for a in result.adjustments), result.score)

    def test_render_shows_the_working(self):
        result = score_finding("critical", {"internet_facing": True,
                                            "accepted_risk": True})
        rendered = result.render()
        self.assertIn("P", rendered)
        self.assertIn("internet-facing", rendered)
        self.assertIn("accepted", rendered.lower())

    def test_accepted_risk_render_warns_against_auto_filing(self):
        rendered = score_finding("high", {"accepted_risk": True}).render()
        self.assertIn("do not auto-file", rendered.lower())


class TestRealisticFindings(unittest.TestCase):
    """End-to-end shapes matching the demo's own findings, so a regression in
    the weighting shows up as a changed priority rather than a changed digit."""

    def test_internet_facing_tier1_critical_is_p1(self):
        result = score_finding("critical", {
            "internet_facing": True, "data_classification": "PII+PCI",
            "regulatory_scope": ["PCI-DSS", "UK-GDPR"],
            "asset_criticality": "tier1",
        })
        self.assertEqual(result.priority, "P1")

    def test_accepted_unreachable_medium_drops_to_p4(self):
        """The down-rank case the demo leans on: a Medium that is unreachable,
        WAF-covered and formally accepted should not page anyone."""
        result = score_finding("medium", {
            "internet_facing": True, "reachable": False,
            "data_classification": "PII+PCI", "control_covers": True,
            "accepted_risk": True,
        })
        self.assertEqual(result.priority, "P4")
        self.assertTrue(result.accepted_risk)

    def test_context_can_outrank_technical_severity(self):
        """The whole thesis: a Medium in a bad place must be able to outrank a
        Critical in a safe one. If this fails, sorting by CVSS was fine after
        all and the product has no reason to exist."""
        medium_exposed = score_finding("medium", {
            "internet_facing": True, "active_exploit": True,
            "data_classification": "PII+PCI", "asset_criticality": "tier1",
        })
        critical_contained = score_finding("critical", {
            "internet_facing": False, "reachable": False,
            "accepted_risk": True,
        })
        self.assertGreater(medium_exposed.score, critical_contained.score)


if __name__ == "__main__":
    unittest.main()
