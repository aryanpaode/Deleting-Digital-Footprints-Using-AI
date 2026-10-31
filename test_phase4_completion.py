import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import phase4_mail as mail
import phase4_verification as verify


class CompletionTests(unittest.TestCase):
    def test_pkce_and_provider_capability(self):
        verifier, challenge = mail.create_pkce_pair()
        self.assertGreater(len(verifier), 40)
        self.assertTrue(challenge)

        gmail = mail.mail_capability_for_address("demo@gmail.com")
        self.assertTrue(gmail["automatic_oauth_supported"])
        self.assertEqual(gmail["provider"], "Gmail")

        rediff = mail.mail_capability_for_address("demo@rediffmail.com")
        self.assertFalse(rediff["automatic_oauth_supported"])
        self.assertTrue(rediff["manual_fallback"])

    def test_gmail_send_response_proves_sent_label_without_mailbox_read_scope(self):
        evidence = mail._sent_response_evidence(
            {
                "id": "18cabc123",
                "threadId": "18cabc100",
                "labelIds": ["SENT"],
            },
            sender="demo@gmail.com",
            recipient="privacy@example.com",
            subject="Removal Request [DFR-ABC123]",
            reference="DFR-ABC123",
            message_sha256="deadbeef",
            rfc_message_id="<test@gmail.com>",
        )
        self.assertTrue(evidence["provider_accepted"])
        self.assertTrue(evidence["verified"])
        self.assertEqual(evidence["provider_message_id"], "18cabc123")
        self.assertIn("SENT", evidence["gmail_label_ids"])
        self.assertEqual(evidence["method"], "gmail_api_email")

    def test_google_workspace_domain_can_be_opted_in_locally(self):
        with patch.dict("os.environ", {"GOOGLE_WORKSPACE_DOMAINS": "example.edu,example.org"}, clear=False):
            capability = mail.mail_capability_for_address("student@example.edu")
            self.assertTrue(capability["automatic_oauth_supported"])

    def test_verification_distinguishes_security_action_from_removal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vdir = root / "verification"
            pending = vdir / "pending_rescan.json"
            latest = vdir / "latest_verification.json"
            history = vdir / "verification_history.jsonl"
            with patch.multiple(
                verify,
                VERIFICATION_DIR=vdir,
                PENDING_FILE=pending,
                LATEST_FILE=latest,
                HISTORY_FILE=history,
            ):
                phase4_state = {
                    "source_run_id": "before-run",
                    "source_phase3_run_time": "before-time",
                    "overall_risk": {"score": 80, "level": "Critical"},
                    "summary": {"completed_actions": 2},
                    "tasks": [
                        {
                            "task_id": "P4-PASS",
                            "finding_id": "P2B-BREACH-001",
                            "recommended_action": "change_password",
                            "status": "completed",
                            "outcome": "remediated",
                            "target": {
                                "finding_type": "breach_exposure",
                                "label": "Example Breach",
                                "service": "Example",
                                "domain": "example.com",
                                "breach_date": "2020-01-01",
                            },
                            "execution": {"selected_scope": {}},
                            "verification": {},
                        },
                        {
                            "task_id": "P4-PUBLIC",
                            "finding_id": "P2A-001",
                            "recommended_action": "delete_account_or_content",
                            "status": "completed",
                            "outcome": "remediated",
                            "target": {
                                "finding_type": "public_footprint",
                                "label": "Old public page",
                                "url": "https://example.org/old-page",
                                "domain": "example.org",
                            },
                            "execution": {"selected_scope": {}},
                            "verification": {},
                        },
                    ],
                }
                profile = {
                    "full_name": "Test User",
                    "email": "test@example.com",
                    "username": "testuser",
                }
                aggregate_before = {"run_id": "before-run", "input_profile": profile}
                phase3_before = {
                    "cross_layer_assessment": {
                        "overall_risk_score": 80,
                        "overall_risk_level": "Critical",
                    }
                }
                verify.create_pending_baseline(
                    phase4_state,
                    aggregate_before,
                    phase3_before,
                )

                aggregate_after = {
                    "artifact_type": "aggregated_footprint_report",
                    "version": 1,
                    "run_id": "after-run",
                    "input_profile": profile,
                    "layers": {
                        "phase_2A_public": {"results": [], "visual_review_items": []},
                        "phase_2B_breach_and_broker": {
                            "breach_exposures": [
                                {
                                    "service": "Example",
                                    "domain": "example.com",
                                    "breach_date": "2020-01-01",
                                    "exposed_data": ["Passwords"],
                                }
                            ],
                            "data_broker_exposures": [],
                        },
                        "phase_2C_local_passive": {"browser_profiles": []},
                    },
                }
                phase3_after = {
                    "cross_layer_assessment": {
                        "overall_risk_score": 50,
                        "overall_risk_level": "High",
                    }
                }
                report = verify.finalize_pending_if_possible(
                    aggregate_after,
                    phase3_after,
                )
                by_task = {item["task_id"]: item for item in report["results"]}
                self.assertEqual(
                    by_task["P4-PASS"]["result"],
                    "security_action_self_confirmed",
                )
                self.assertEqual(
                    by_task["P4-PUBLIC"]["result"],
                    "verified_removed_or_unavailable",
                )
                self.assertTrue(by_task["P4-PUBLIC"]["verified"])
                self.assertEqual(report["after_risk"]["score"], 50)


if __name__ == "__main__":
    unittest.main()
