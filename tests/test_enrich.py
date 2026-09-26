"""Tests for context enrichment.

Enrichment is where a raw scanner finding becomes a business decision. The
risks worth testing are the quiet ones: claiming a control that isn't there,
missing an accepted risk and re-escalating it, or filing a duplicate ticket.
"""

import unittest

from core.safety import EvidenceStatus
from scenarios.appsec.enrich import enrich_findings, _control_covers, _cve_of


def finding(**overrides):
    base = {
        "id": "F-1", "type": "SCA", "severity": "high",
        "title": "lodash <4.17.21 prototype pollution (CVE-2021-23337)",
        "repo": "payments-service", "file": "package-lock.json",
        "reachable": True, "fix": "upgrade",
    }
    base.update(overrides)
    return base


ASSETS = {
    "payments-service": {
        "internet_facing": True,
        "environments_deployed": ["prod"],
        "data_classification": "PII+PCI",
        "regulatory_scope": ["PCI-DSS"],
        "asset_criticality": "tier1",
        "compensating_controls": ["WAF"],
    }
}

ACCEPTED = {
    "accepted_risks": [{
        "risk_id": "RR-2041",
        "matches": {"cve": "CVE-2023-45857"},
        "accepted_by": "Head of Engineering",
        "review_date": "2026-09-30",
        "rationale": "Not reachable from an untrusted path.",
    }]
}

TICKETING = [{"key": "SEC-318", "status": "In Progress",
         "links": {"cve": "CVE-2023-45857"}}]

EXPLOIT = {"CVE-2021-23337": {"kev": True, "epss": 0.42, "note": "exploited"}}


def enrich_one(f, **overrides):
    kwargs = dict(assets=ASSETS, accepted=ACCEPTED, ticketing=TICKETING,
                  exploit=EXPLOIT, live=False)
    kwargs.update(overrides)
    return enrich_findings([f], **kwargs)[0]


class TestCveExtraction(unittest.TestCase):

    def test_cve_is_pulled_from_the_title(self):
        self.assertEqual(_cve_of(finding()), "CVE-2021-23337")

    def test_cve_is_normalised_to_uppercase(self):
        self.assertEqual(_cve_of(finding(title="cve-2021-23337 in lodash")),
                         "CVE-2021-23337")

    def test_finding_without_a_cve_yields_none(self):
        self.assertIsNone(_cve_of(finding(title="SQL string concatenation")))

    def test_missing_title_does_not_raise(self):
        self.assertIsNone(_cve_of({}))


class TestBusinessContext(unittest.TestCase):

    def test_asset_context_is_attached(self):
        result = enrich_one(finding())
        self.assertTrue(result.context["internet_facing"])
        self.assertEqual(result.context["data_classification"], "PII+PCI")
        self.assertEqual(result.context["asset_criticality"], "tier1")

    def test_unknown_repo_is_labelled_unknown_not_assumed_safe(self):
        """The failure mode that matters: an unrecognised repo must produce an
        explicit UNKNOWN, never a quiet default that down-ranks the finding."""
        result = enrich_one(finding(repo="not-in-inventory"))
        statuses = [e.status for e in result.evidence]
        self.assertIn(EvidenceStatus.UNKNOWN, statuses)
        self.assertNotIn("internet_facing", result.context)

    def test_deployment_is_derived_from_environments(self):
        self.assertTrue(enrich_one(finding()).context["deployed"])

    def test_non_prod_asset_is_not_marked_deployed(self):
        assets = {"payments-service": dict(ASSETS["payments-service"],
                                           environments_deployed=["staging"])}
        self.assertFalse(enrich_one(finding(), assets=assets).context["deployed"])


class TestControlCoverage(unittest.TestCase):
    """Claiming a control that does not apply would silently suppress a real
    finding, so coverage is deliberately conservative."""

    def test_waf_covers_injection_classes(self):
        asset = ASSETS["payments-service"]
        for title in ("SQL string concatenation in user lookup",
                      "axios SSRF (CVE-2023-45857)",
                      "Reflected XSS in search"):
            with self.subTest(title=title):
                self.assertTrue(_control_covers({"title": title, "type": ""}, asset))

    def test_waf_does_not_cover_unrelated_classes(self):
        asset = ASSETS["payments-service"]
        for title in ("Hardcoded storage key in commit history",
                      "Outdated TLS cipher suite",
                      "lodash prototype pollution"):
            with self.subTest(title=title):
                self.assertFalse(_control_covers({"title": title, "type": ""}, asset))

    def test_no_coverage_claimed_when_the_asset_lacks_the_control(self):
        bare = {"compensating_controls": []}
        self.assertFalse(_control_covers({"title": "SQL injection", "type": ""}, bare))

    def test_no_coverage_claimed_for_unknown_asset(self):
        self.assertFalse(_control_covers({"title": "SQL injection", "type": ""}, {}))


class TestAcceptedRisk(unittest.TestCase):

    def test_accepted_risk_is_matched_by_cve(self):
        result = enrich_one(finding(title="axios SSRF (CVE-2023-45857)"))
        self.assertTrue(result.context["accepted_risk"])
        self.assertTrue(result.score.accepted_risk)

    def test_unaccepted_finding_is_not_flagged(self):
        self.assertFalse(enrich_one(finding()).context["accepted_risk"])

    def test_acceptance_evidence_names_the_register_entry(self):
        result = enrich_one(finding(title="axios SSRF (CVE-2023-45857)"))
        claims = " ".join(e.claim for e in result.evidence)
        self.assertIn("RR-2041", claims)
        self.assertIn("Head of Engineering", claims)


class TestDuplicateTickets(unittest.TestCase):
    """Filing a duplicate is how an agent loses a team's trust fastest."""

    def test_existing_ticket_is_linked(self):
        result = enrich_one(finding(title="axios SSRF (CVE-2023-45857)"))
        self.assertIsNotNone(result.linked_ticket)
        self.assertEqual(result.linked_ticket["key"], "SEC-318")

    def test_unrelated_finding_links_no_ticket(self):
        self.assertIsNone(enrich_one(finding()).linked_ticket)

    def test_linked_ticket_evidence_warns_against_duplicating(self):
        result = enrich_one(finding(title="axios SSRF (CVE-2023-45857)"))
        claims = " ".join(e.claim for e in result.evidence).lower()
        self.assertIn("duplicate", claims)


class TestExploitIntel(unittest.TestCase):

    def test_known_exploited_cve_sets_active_exploit(self):
        self.assertTrue(enrich_one(finding()).context["active_exploit"])

    def test_cve_absent_from_the_feed_is_unknown_not_false(self):
        """'Not in the feed' means we do not know. Recording False would let a
        missing record read as evidence of safety."""
        result = enrich_one(finding(title="something (CVE-1999-0001)"))
        self.assertIsNone(result.context["active_exploit"])
        self.assertIn(EvidenceStatus.UNKNOWN, [e.status for e in result.evidence])


class TestProvenanceLabelling(unittest.TestCase):
    """Live and simulated data must never be presented identically."""

    def test_simulated_run_labels_evidence_simulated(self):
        statuses = [e.status for e in enrich_one(finding(), live=False).evidence]
        self.assertIn(EvidenceStatus.SIMULATED, statuses)
        self.assertNotIn(EvidenceStatus.CONFIRMED, statuses)

    def test_live_run_labels_evidence_confirmed(self):
        statuses = [e.status for e in enrich_one(finding(), live=True).evidence]
        self.assertIn(EvidenceStatus.CONFIRMED, statuses)
        self.assertNotIn(EvidenceStatus.SIMULATED, statuses)

    def test_every_piece_of_evidence_carries_a_source(self):
        for ev in enrich_one(finding()).evidence:
            with self.subTest(claim=ev.claim[:40]):
                self.assertTrue(ev.source.strip())


class TestEnrichmentBatch(unittest.TestCase):

    def test_every_finding_is_returned_with_a_score(self):
        findings = [finding(id="F-1"),
                    finding(id="F-2", title="SQL string concatenation"),
                    finding(id="F-3", title="axios SSRF (CVE-2023-45857)")]
        results = enrich_findings(findings, assets=ASSETS, accepted=ACCEPTED,
                                  ticketing=TICKETING, exploit=EXPLOIT, live=False)
        self.assertEqual(len(results), 3)
        for r in results:
            with self.subTest(finding=r.finding["id"]):
                self.assertIn(r.score.priority, {"P1", "P2", "P3", "P4"})

    def test_empty_input_yields_empty_output(self):
        self.assertEqual(enrich_findings([], assets=ASSETS, accepted=ACCEPTED,
                                         ticketing=TICKETING, exploit=EXPLOIT, live=False), [])


if __name__ == "__main__":
    unittest.main()
