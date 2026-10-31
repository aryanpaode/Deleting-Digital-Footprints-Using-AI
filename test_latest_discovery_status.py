import unittest
import sys
import types

# Unit tests do not call OpenAI; provide a tiny import stub if the package is
# unavailable in this sandbox. Real project environments still use openai.
try:
    import openai  # noqa: F401
except ModuleNotFoundError:
    stub = types.ModuleType("openai")
    class _OpenAI:
        pass
    stub.OpenAI = _OpenAI
    sys.modules["openai"] = stub

import phase2_core_v4 as core
import phase2A_public as p2a
import run_phase3 as p3


class LatestDiscoveryStatusTests(unittest.TestCase):
    def test_email_is_additive_query_not_replacement(self):
        plan = core.generate_web_query_plan(
            full_name="Example Person",
            email="person@example.com",
            username="exampleperson",
        )
        purposes = {item["purpose"]: item for item in plan}
        self.assertIn("public_identity_without_email", purposes)
        self.assertIn("exact_email_corroboration", purposes)
        self.assertFalse(purposes["public_identity_without_email"]["includes_email"])
        self.assertTrue(purposes["exact_email_corroboration"]["includes_email"])
        self.assertNotIn("person@example.com", purposes["public_identity_without_email"]["query"])
        self.assertIn("person@example.com", purposes["exact_email_corroboration"]["query"])

    def test_exact_email_can_confirm_without_name(self):
        profile = {
            "full_name": "Example Person",
            "email": "person@example.com",
            "username": "",
            "phone": "",
            "context_terms": [],
        }
        candidates = [{
            "source": "Tavily Web Search",
            "source_type": "web",
            "title": "Contact page",
            "snippet": "For enquiries contact person@example.com",
            "url": "https://example.org/contact",
            "fetch_status": "not_required",
        }]
        result = p2a.analyze_candidates(candidates, profile)[0]
        self.assertEqual(result["identity_status"], "Confirmed")
        self.assertEqual(result["identity_score"], 100)
        self.assertEqual(result.get("association_basis"), "exact_supplied_email")
        self.assertIn("independent positive identity anchor", " ".join(result["match_reasons"]))

    def test_targeted_search_is_broad_platform_set(self):
        queries = p2a.build_targeted_profile_queries({
            "full_name": "Example Person",
            "username": "exampleperson",
        })
        text = "\n".join(item["query"] for item in queries).lower()
        for domain in (
            "linkedin.com", "researchgate.net", "ieeexplore.ieee.org",
            "orcid.org", "scholar.google.com", "semanticscholar.org",
            "kaggle.com", "stackoverflow.com", "github.com", "gitlab.com",
            "medium.com", "facebook.com", "instagram.com", "x.com",
        ):
            self.assertIn(domain, text)

    def test_degree_is_not_organization_and_nmims_mpstme_are(self):
        text = (
            "Arjun MEHRA | Student | Bachelor of Technology | "
            "Narsee Monjee Institute of Management Studies. "
            "Student at Mukesh Patel School of Technology Management & Engineering (MPSTME)."
        )
        orgs = p2a.extract_organizations(text)
        self.assertIn("NMIMS", orgs)
        self.assertIn("MPSTME", orgs)
        self.assertNotIn("Bachelor of Technology", orgs)

    def test_public_associations_for_student_use_institution_not_degree(self):
        report = {
            "input_profile": {"full_name": "Arjun Mehra"},
            "layers": {
                "phase_2A_public": {
                    "results": [{
                        "title": (
                            "Arjun MEHRA | Student | Bachelor of Technology | "
                            "Narsee Monjee Institute of Management Studies"
                        ),
                        "snippet": (
                            "Student at Mukesh Patel School of Technology "
                            "Management & Engineering (MPSTME)."
                        ),
                        "url": "https://example.com/student-profile",
                        "source_category": "Academic profile",
                        "identity_status": "Confirmed",
                        "identity_score": 100,
                        "published_date": "",
                        "entities": {
                            "job_titles": ["student"],
                            "organizations": [
                                "Bachelor of Technology",
                                "Narsee Monjee Institute of Management Studies",
                                "Mukesh Patel School of Technology Management & Engineering",
                            ],
                        },
                    }]
                }
            }
        }
        analyses = [{"finding_id": "P2A-001", "user_verification": "not_required"}]
        associations = p3.build_public_associations(report, analyses)
        self.assertIn("NMIMS", associations["organizations"])
        self.assertIn("MPSTME", associations["organizations"])
        self.assertNotIn("Bachelor of Technology", associations["organizations"])
        self.assertIn("Student", associations["roles"])
        self.assertNotIn("status", associations)
        self.assertNotIn("current_organization", associations)

    def test_professional_associations_list_multiple_orgs_without_current_claim(self):
        report = {
            "input_profile": {"full_name": "Example Person"},
            "layers": {
                "phase_2A_public": {
                    "results": [
                        {
                            "title": "Example Person appointed CEO - Shriram Equipment Finance Company Limited",
                            "snippet": "Example Person served as chief executive officer.",
                            "url": "https://news.example.com/one",
                            "source_category": "News/industry article",
                            "identity_status": "Possible",
                            "identity_score": 58,
                            "published_date": "",
                            "entities": {
                                "job_titles": ["chief executive officer"],
                                "organizations": ["Shriram Equipment Finance Company Limited"],
                            },
                        },
                        {
                            "title": "Example Person - SREI Equipment Finance Limited",
                            "snippet": "Business Head at SREI Equipment Finance Limited.",
                            "url": "https://example.com/two",
                            "source_category": "Professional profile",
                            "identity_status": "Possible",
                            "identity_score": 58,
                            "published_date": "",
                            "entities": {
                                "job_titles": ["business head"],
                                "organizations": ["SREI Equipment Finance Limited"],
                            },
                        },
                        {
                            "title": "Example Person - Magma Fincorp Ltd.",
                            "snippet": "Senior Vice President at Magma Fincorp Ltd.",
                            "url": "https://example.com/three",
                            "source_category": "Professional profile",
                            "identity_status": "Possible",
                            "identity_score": 58,
                            "published_date": "2024-01-01T00:00:00Z",
                            "entities": {
                                "job_titles": ["vice president"],
                                "organizations": ["Magma Fincorp Ltd."],
                            },
                        },
                    ]
                }
            }
        }
        analyses = [
            {"finding_id": "P2A-001", "user_verification": "confirmed"},
            {"finding_id": "P2A-002", "user_verification": "confirmed"},
            {"finding_id": "P2A-003", "user_verification": "confirmed"},
        ]
        associations = p3.build_public_associations(report, analyses)
        self.assertIn("Shriram Equipment Finance Company Limited", associations["organizations"])
        self.assertIn("SREI Equipment Finance Limited", associations["organizations"])
        self.assertIn("Magma Fincorp Ltd", associations["organizations"])
        self.assertIn("Chief Executive Officer", associations["roles"])
        self.assertIn("Business Head", associations["roles"])
        self.assertIn("Senior Vice President", associations["roles"])
        self.assertEqual(associations["confidence"], "Low")  # Single-source claims; no repeated corroboration.
        self.assertIn(associations["evidence_recency"], {"Mixed", "Mixed / mostly undated"})
        self.assertIn("no current status is inferred", associations["summary"])

    def test_entity_metadata_without_subject_linked_text_is_not_enough(self):
        report = {
            "input_profile": {"full_name": "Example Person"},
            "layers": {
                "phase_2A_public": {
                    "results": [
                        {
                            "title": "Example Person profile",
                            "snippet": "Example Person is a Business Head at SREI EQUIPMENT FINANCE LIMITED.",
                            "url": "https://example.com/1",
                            "source_category": "Professional profile",
                            "identity_status": "Possible",
                            "identity_score": 58,
                            "entities": {
                                "job_titles": ["business head"],
                                "organizations": [
                                    "a Business Head at SREI EQUIPMENT FINANCE LIMITED. Example Person",
                                    "appointment As on Designation SHRIRAM EQUIPMENT FINANCE COMPANY LIMITED",
                                    "and Sr Vice- President of Magma Fincorp Limited",
                                    "are from various industries such as Finance etc. More Details",
                                    "Shriram Automall India Limited",
                                    "Extra Example Company Limited",
                                ],
                            },
                        },
                    ]
                }
            }
        }
        analyses = [{"finding_id": "P2A-001", "user_verification": "confirmed"}]
        associations = p3.build_public_associations(report, analyses)
        orgs = associations["organizations"]
        self.assertEqual(orgs, ["SREI EQUIPMENT FINANCE LIMITED"])
        self.assertIn("SREI EQUIPMENT FINANCE LIMITED", orgs)
        self.assertNotIn("SHRIRAM EQUIPMENT FINANCE COMPANY LIMITED", orgs)
        self.assertNotIn("Magma Fincorp Limited", orgs)
        self.assertTrue(all("Business Head" not in value for value in orgs))
        self.assertTrue(all("appointment" not in value.casefold() for value in orgs))
        self.assertTrue(all("various industries" not in value.casefold() for value in orgs))



    def test_generic_college_and_prose_are_not_organizations(self):
        self.assertEqual(p3._canonical_org("college"), "")
        self.assertEqual(p3._canonical_org("a top engineering college in Mumbai was"), "")

    def test_faculty_role_beats_noisy_student_and_orgs_are_clean(self):
        report = {
            "input_profile": {"full_name": "Faculty Example"},
            "layers": {
                "phase_2A_public": {
                    "results": [{
                        "title": "Faculty Example | MPSTME | NMIMS",
                        "snippet": "Faculty Example is an Assistant Professor at MPSTME, NMIMS.",
                        "extracted_content": (
                            "Faculty Example is an Assistant Professor in the department. "
                            "She teaches at Mukesh Patel School of Technology Management & Engineering."
                        ),
                        "url": "https://example.edu/faculty",
                        "source_category": "Academic profile",
                        "identity_status": "Confirmed",
                        "identity_score": 100,
                        "entities": {
                            "job_titles": ["student"],
                            "organizations": [
                                "NMIMS",
                                "MPSTME",
                                "college",
                                "a top engineering college in Mumbai was",
                            ],
                        },
                    }]
                }
            },
        }
        analyses = [{"finding_id": "P2A-001", "user_verification": "not_required"}]
        associations = p3.build_public_associations(report, analyses)
        self.assertEqual(set(associations["organizations"]), {"NMIMS", "MPSTME"})
        self.assertIn("Assistant Professor", associations["roles"])
        self.assertNotIn("Student", associations["roles"])
        self.assertEqual(associations["roles"][0], "Assistant Professor")

    def test_unverified_public_results_do_not_enter_associations(self):
        report = {
            "layers": {
                "phase_2A_public": {
                    "results": [{
                        "title": "Wrong Person - Example Company Limited",
                        "snippet": "CEO at Example Company Limited",
                        "url": "https://example.com/wrong",
                        "source_category": "Professional profile",
                        "identity_status": "Possible",
                        "identity_score": 55,
                        "entities": {
                            "job_titles": ["chief executive officer"],
                            "organizations": ["Example Company Limited"],
                        },
                    }]
                }
            }
        }
        analyses = [{"finding_id": "P2A-001", "user_verification": "rejected"}]
        associations = p3.build_public_associations(report, analyses)
        self.assertEqual(associations["organizations"], [])
        self.assertEqual(associations["roles"], [])
        self.assertEqual(associations["verified_evidence_count"], 0)


if __name__ == "__main__":
    unittest.main()
