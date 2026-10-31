import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import phase4_remediation as p4


class Phase4Tests(unittest.TestCase):
    def make_project_data(self, root: Path):
        reports = root / "reports"
        (reports / "phase3").mkdir(parents=True)
        (reports / "aggregate").mkdir(parents=True)

        profile_path = root / "Chrome" / "Default"
        (profile_path / "Network").mkdir(parents=True)
        cookie_db = profile_path / "Network" / "Cookies"

        con = sqlite3.connect(cookie_db)
        con.execute(
            """
            CREATE TABLE cookies (
                host_key TEXT,
                name TEXT,
                path TEXT,
                expires_utc INTEGER DEFAULT 0,
                is_secure INTEGER DEFAULT 0,
                is_httponly INTEGER DEFAULT 0,
                samesite INTEGER DEFAULT 0,
                is_persistent INTEGER DEFAULT 1
            )
            """
        )
        con.executemany(
            "INSERT INTO cookies(host_key, name, path) VALUES (?, ?, ?)",
            [
                (".doubleclick.net", "IDE", "/"),
                (".example.com", "sessionid", "/"),
                (".example.com", "preferences", "/"),
            ],
        )
        con.commit()
        con.close()

        action_plan = {
            "artifact_type": "phase3_action_plan",
            "phase": 3,
            "version": 2,
            "run_time": "2026-09-11T12:00:00+00:00",
            "source_run_id": "run-test",
            "overall_risk": {"score": 60, "level": "High"},
            "actions": [
                {
                    "finding_id": "P2C-001",
                    "ai_classification": "mixed_local_browser_privacy",
                    "risk_score": 60,
                    "risk_level": "High",
                    "recommended_action": "clear_selected_local_data",
                    "action_reason": "Selective cleanup recommended.",
                    "requires_user_approval": True,
                    "priority_score": 60,
                },
                {
                    "finding_id": "P2B-BREACH-001",
                    "ai_classification": "breach_exposure",
                    "risk_score": 85,
                    "risk_level": "Critical",
                    "recommended_action": "change_password",
                    "action_reason": "Credential exposure requires remediation.",
                    "requires_user_approval": True,
                    "priority_score": 85,
                },
                {
                    "finding_id": "P2A-001",
                    "ai_classification": "professional_public_presence",
                    "risk_score": 10,
                    "risk_level": "Low",
                    "recommended_action": "review",
                    "action_reason": "Review the public profile.",
                    "requires_user_approval": False,
                    "priority_score": 10,
                },
            ],
        }

        analysis = {
            "artifact_type": "phase3_ai_analysis",
            "phase": 3,
            "version": 2,
            "run_time": "2026-09-11T12:00:00+00:00",
            "source_run_id": "run-test",
            "analyses": [
                {
                    "finding_id": "P2C-001",
                    "user_verification": "not_required",
                    "verification_reassessment_performed": False,
                    "risk_explanation": "Tracker metadata found.",
                },
                {
                    "finding_id": "P2B-BREACH-001",
                    "user_verification": "not_required",
                    "verification_reassessment_performed": False,
                    "risk_explanation": "Password-related breach.",
                },
                {
                    "finding_id": "P2A-001",
                    "user_verification": "confirmed",
                    "verification_reassessment_performed": True,
                    "risk_explanation": "Public professional profile.",
                },
            ],
        }

        aggregate = {
            "artifact_type": "aggregated_footprint_report",
            "version": 1,
            "run_id": "run-test",
            "layers": {
                "phase_2A_public": {
                    "results": [
                        {
                            "title": "Professional profile",
                            "canonical_url": "https://example.com/profile",
                            "source_category": "Professional profile",
                            "identity_status": "Strong",
                        }
                    ],
                    "visual_review_items": [],
                },
                "phase_2B_breach_and_broker": {
                    "breach_exposures": [
                        {
                            "service": "Example Service",
                            "domain": "example.com",
                            "breach_date": "2024-01-01",
                            "exposed_data": ["Passwords"],
                            "password_risk": "high",
                            "provider_sources": ["test"],
                        }
                    ],
                    "data_broker_exposures": [],
                },
                "phase_2C_local_passive": {
                    "browser_profiles": [
                        {
                            "browser": "Google Chrome",
                            "profile_name": "Default",
                            "profile_path": str(profile_path),
                            "summary": {
                                "cookie_count": 3,
                                "persistent_cookie_count": 3,
                                "potential_tracker_cookie_count": 1,
                                "risky_allowed_permission_count": 0,
                            },
                            "potential_tracker_domains": [
                                {"domain": "doubleclick.net", "cookie_count": 1}
                            ],
                            "risky_permissions": [],
                        }
                    ]
                },
            },
        }

        (reports / "phase3" / "latest_action_plan.json").write_text(
            json.dumps(action_plan), encoding="utf-8"
        )
        (reports / "phase3" / "latest_phase3_analysis.json").write_text(
            json.dumps(analysis), encoding="utf-8"
        )
        (reports / "aggregate" / "latest_aggregate_internal.json").write_text(
            json.dumps(aggregate), encoding="utf-8"
        )
        return reports, cookie_db

    def patched_paths(self, reports: Path):
        return patch.multiple(
            p4,
            REPORTS_DIR=reports,
            PHASE4_DIR=reports / "phase4",
            PHASE3_ACTION_PLAN_FILE=reports / "phase3" / "latest_action_plan.json",
            PHASE3_ANALYSIS_FILE=reports / "phase3" / "latest_phase3_analysis.json",
            AGGREGATE_FILE=reports / "aggregate" / "latest_aggregate_internal.json",
            LATEST_STATE_FILE=reports / "phase4" / "latest_phase4_state.json",
            LATEST_SHAREABLE_STATE_FILE=reports / "phase4" / "latest_phase4_shareable.json",
            HISTORY_FILE=reports / "phase4" / "phase4_history.jsonl",
            BACKUP_DIR=reports / "phase4" / "backups",
        )

    def test_current_project_action_plan_maps_one_to_one(self):
        if not p4.PHASE3_ACTION_PLAN_FILE.exists():
            self.skipTest("Current project reports are not included in the safe update ZIP.")
        action_plan = json.loads(p4.PHASE3_ACTION_PLAN_FILE.read_text(encoding="utf-8"))
        state = p4.load_or_initialize_state()
        self.assertEqual(
            state["summary"]["total_tasks"],
            len(action_plan.get("actions", [])),
        )
        self.assertEqual(
            {task["finding_id"] for task in state["tasks"]},
            {item["finding_id"] for item in action_plan.get("actions", [])},
        )

        broker_tasks = [
            task for task in state["tasks"]
            if (task.get("target") or {}).get("finding_type") == "data_broker_exposure"
        ]
        for broker in broker_tasks:
            self.assertIn("url", broker["target"])

    def test_approval_gate_and_manual_tracking(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                breach = next(t for t in state["tasks"] if t["finding_id"] == "P2B-BREACH-001")
                self.assertEqual(breach["status"], "awaiting_approval")
                with self.assertRaises(PermissionError):
                    # Directly trying to start before approval must fail.
                    p4.transition_task(state, breach["task_id"], "in_progress")

                p4.approve_task(state, breach["task_id"])
                p4.transition_task(state, breach["task_id"], "in_progress")
                p4.transition_task(state, breach["task_id"], "completed")
                self.assertEqual(breach["status"], "completed")

    def test_bulk_decision_table_resolves_all_pending_rows(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                by_finding = {task["finding_id"]: task for task in state["tasks"]}

                decisions = {
                    by_finding["P2C-001"]["task_id"]: "skip",
                    by_finding["P2B-BREACH-001"]["task_id"]: "approve",
                    by_finding["P2A-001"]["task_id"]: "retain",
                }
                counts = p4.apply_bulk_decisions(state, decisions)

                self.assertEqual(counts, {"approved": 1, "retained": 1, "skipped": 1})
                self.assertEqual(state["summary"]["decision_pending"], 0)
                self.assertEqual(state["summary"]["ready"], 1)
                self.assertEqual(state["summary"]["retained"], 1)
                self.assertEqual(state["summary"]["skipped"], 1)
                self.assertFalse(state["summary"]["plan_resolved"])

                breach = by_finding["P2B-BREACH-001"]
                self.assertEqual(breach["approval"]["decision"], "approved")
                self.assertEqual(breach["status"], "not_started")
                self.assertEqual(breach["outcome"], "approved")

    def test_bulk_decision_table_rejects_incomplete_submission(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                only_one = state["tasks"][0]
                with self.assertRaises(ValueError):
                    p4.apply_bulk_decisions(
                        state,
                        {only_one["task_id"]: "skip"},
                    )

    def test_local_cleanup_deletes_only_selected_tracker_rows(self):
        with tempfile.TemporaryDirectory() as td:
            reports, cookie_db = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                cleanup = next(t for t in state["tasks"] if t["finding_id"] == "P2C-001")

                preview = p4.preview_local_tracker_cleanup(
                    state,
                    cleanup["task_id"],
                    domain_groups=["doubleclick.net"],
                )
                self.assertEqual(preview["tracker_rows_matched"], 1)
                self.assertFalse(preview["safety"]["cookie_values_read"])

                p4.approve_task(state, cleanup["task_id"])
                result = p4.execute_local_tracker_cleanup(
                    state,
                    cleanup["task_id"],
                    domain_groups=["doubleclick.net"],
                    confirmed=True,
                )
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["rows_deleted"], 1)
                self.assertEqual(result["tracker_rows_after"], 0)

                con = sqlite3.connect(cookie_db)
                rows = con.execute("SELECT host_key, name FROM cookies ORDER BY name").fetchall()
                con.close()
                self.assertNotIn((".doubleclick.net", "IDE"), rows)
                self.assertIn((".example.com", "sessionid"), rows)
                self.assertIn((".example.com", "preferences"), rows)

                backup_root = reports / "phase4" / "backups" / cleanup["task_id"]
                self.assertTrue(backup_root.exists())
                self.assertTrue(any((folder / "Cookies").exists() for folder in backup_root.iterdir()))

    def test_new_phase3_generation_invalidates_old_approval(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                breach = next(t for t in state["tasks"] if t["finding_id"] == "P2B-BREACH-001")
                p4.approve_task(state, breach["task_id"])
                self.assertEqual(breach["approval"]["decision"], "approved")

                action_path = reports / "phase3" / "latest_action_plan.json"
                action_plan = json.loads(action_path.read_text(encoding="utf-8"))
                action_plan["run_time"] = "2026-09-11T13:00:00+00:00"
                action_path.write_text(json.dumps(action_plan), encoding="utf-8")

                refreshed = p4.load_or_initialize_state()
                refreshed_breach = next(
                    t for t in refreshed["tasks"] if t["finding_id"] == "P2B-BREACH-001"
                )
                self.assertEqual(refreshed_breach["approval"]["decision"], "pending")
                self.assertEqual(refreshed_breach["status"], "awaiting_approval")

    def test_shareable_state_removes_private_browser_path(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                p4.initialize_state(force=True)
                shareable = json.loads(
                    (reports / "phase4" / "latest_phase4_shareable.json").read_text(encoding="utf-8")
                )
                cleanup = next(t for t in shareable["tasks"] if t["finding_id"] == "P2C-001")
                self.assertNotIn("private_target", cleanup)

    def test_broker_email_preview_and_sent_items_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                broker_action = {
                    "finding_id": "P2B-BROKER-001",
                    "ai_classification": "data_broker_exposure",
                    "risk_score": 55,
                    "risk_level": "Medium",
                    "recommended_action": "broker_opt_out",
                    "action_reason": "Confirmed broker record can be removed where permitted.",
                    "requires_user_approval": True,
                    "priority_score": 55,
                }
                broker_source = {
                    "finding_id": "P2B-BROKER-001",
                    "layer": "2B",
                    "finding_type": "data_broker_exposure",
                    "label": "Example Broker",
                    "provider": "Example Broker",
                    "domain": "broker.example",
                    "url": "https://broker.example/record/123",
                    "contact_email": "privacy@broker.example",
                    "contact_source_url": "https://broker.example/privacy",
                    "removal_scope_note": "Removal subject to provider policy.",
                }
                task = p4.build_task(
                    "run-test",
                    "2026-09-11T12:00:00+00:00",
                    broker_action,
                    broker_source,
                    {},
                )
                state["tasks"].append(task)
                p4.approve_task(state, task["task_id"])
                preview = p4.build_broker_email_preview(
                    state,
                    task["task_id"],
                    {
                        "full_name": "Test User",
                        "email": "test@example.com",
                        "phone": "+91-9999999999",
                    },
                )
                self.assertEqual(preview["recipient"], "privacy@broker.example")
                self.assertIn("Test User", preview["body"])
                self.assertIn("test@example.com", preview["body"])
                self.assertNotIn("9999999999", preview["body"])
                self.assertIn(preview["reference"], preview["subject"])

                p4.record_broker_email_submission(
                    state,
                    task["task_id"],
                    {
                        "verified": True,
                        "provider_accepted": True,
                        "provider": "Gmail API",
                        "method": "gmail_api_email",
                        "sender": "test@gmail.com",
                        "recipient": preview["recipient"],
                        "subject": preview["subject"],
                        "reference": preview["reference"],
                        "sent_at": "2026-09-11T18:00:00Z",
                        "provider_message_id": "gmail-message-id",
                        "gmail_label_ids": ["SENT"],
                        "message_sha256": "abc123",
                        "rfc_message_id": "<example@gmail.com>",
                        "web_link": "https://mail.google.com/mail/#sent",
                    },
                )
                self.assertEqual(task["status"], "pending_external_confirmation")
                self.assertEqual(task["verification"]["status"], "provider_sent_verified")
                self.assertEqual(
                    task["execution"]["last_result"]["provider_message_id"],
                    "gmail-message-id",
                )

                shareable = json.loads(
                    (reports / "phase4" / "latest_phase4_shareable.json").read_text(encoding="utf-8")
                )
                saved = next(t for t in shareable["tasks"] if t["task_id"] == task["task_id"])
                self.assertNotIn("private_email_request", saved)

    def test_confirmed_broker_review_can_be_upgraded_by_user_to_removal(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                task = p4.build_task(
                    "run-test",
                    "2026-09-11T12:00:00+00:00",
                    {
                        "finding_id": "P2B-BROKER-001",
                        "ai_classification": "data_broker_exposure",
                        "risk_score": 45,
                        "risk_level": "Medium",
                        "recommended_action": "review",
                        "action_reason": "Review confirmed broker exposure.",
                        "requires_user_approval": False,
                        "priority_score": 45,
                    },
                    {
                        "finding_id": "P2B-BROKER-001",
                        "finding_type": "data_broker_exposure",
                        "label": "Example Broker",
                        "provider": "Example Broker",
                        "url": "https://broker.example/record",
                        "contact_email": "privacy@broker.example",
                    },
                    {"user_verification": "confirmed"},
                )
                state = {
                    "artifact_type": "phase4_remediation_state",
                    "phase": 4,
                    "version": p4.PHASE4_VERSION,
                    "source_run_id": "run-test",
                    "source_phase3_run_time": "2026-09-11T12:00:00+00:00",
                    "overall_risk": {"score": 45, "level": "Medium"},
                    "tasks": [task],
                    "summary": {},
                }
                p4.refresh_summary(state)
                counts = p4.apply_bulk_decisions(
                    state,
                    {task["task_id"]: "request_removal"},
                )
                self.assertEqual(counts["approved"], 1)
                self.assertEqual(task["phase3_recommended_action"], "review")
                self.assertEqual(task["user_action_override"], "broker_opt_out")
                self.assertEqual(task["recommended_action"], "broker_opt_out")
                self.assertEqual(task["approval"]["decision"], "approved")
                self.assertEqual(task["execution"]["mode"], "broker_email")

    def test_manual_broker_submission_is_not_mislabelled_provider_verified(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                task = p4.build_task(
                    "run-test",
                    "2026-09-11T12:00:00+00:00",
                    {
                        "finding_id": "P2B-BROKER-001",
                        "ai_classification": "data_broker_exposure",
                        "risk_score": 50,
                        "risk_level": "Medium",
                        "recommended_action": "broker_opt_out",
                        "action_reason": "Remove broker exposure.",
                        "requires_user_approval": True,
                        "priority_score": 50,
                    },
                    {
                        "finding_id": "P2B-BROKER-001",
                        "finding_type": "data_broker_exposure",
                        "label": "Example Broker",
                        "provider": "Example Broker",
                        "url": "https://broker.example/record",
                        "contact_email": "privacy@broker.example",
                    },
                    {"user_verification": "confirmed"},
                )
                state["tasks"].append(task)
                p4.approve_task(state, task["task_id"])
                preview = p4.build_broker_email_preview(
                    state, task["task_id"], {"full_name": "Test User", "email": "test@rediffmail.com"}
                )
                p4.record_broker_manual_submission(
                    state,
                    task["task_id"],
                    sender="test@rediffmail.com",
                    recipient=preview["recipient"],
                    subject=preview["subject"],
                    reference=preview["reference"],
                )
                self.assertEqual(task["status"], "pending_external_confirmation")
                self.assertEqual(task["verification"]["status"], "manual_send_user_confirmed")
                self.assertFalse(task["execution"]["last_result"]["sent_items_verified"])
                self.assertTrue(task["execution"]["last_result"]["user_confirmed_sent"])

    def test_final_report_excludes_private_paths_and_tokens(self):
        with tempfile.TemporaryDirectory() as td:
            reports, _ = self.make_project_data(Path(td))
            with self.patched_paths(reports):
                state = p4.initialize_state(force=True)
                report = p4.build_final_remediation_report(state)
                text = json.dumps(report)
                self.assertNotIn("profile_path", text)
                self.assertNotIn("cookie_database_path", text)
                self.assertNotIn("refresh_token", text)


if __name__ == "__main__":
    unittest.main()
