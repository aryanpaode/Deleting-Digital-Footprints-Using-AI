import time
import unittest
from unittest.mock import patch

import phase2A_public as p2a
import phase2B_exposure as p2b
import phase2_core_v4 as core
import run_all as runner
import visual_identity as visual


class Phase2ParallelTests(unittest.TestCase):
    def test_page_fetches_run_concurrently_and_preserve_order(self):
        results = [
            {"source": "Tavily", "url": f"https://example.com/{i}", "title": str(i)}
            for i in range(6)
        ]

        def fake_fetch(url):
            time.sleep(0.12)
            return {
                "fetch_status": "success",
                "fetch_reason": "",
                "extracted_content": url,
            }

        started = time.perf_counter()
        with patch.object(core, "FETCH_FULL_CONTENT", True), \
             patch.object(core, "PHASE2_FETCH_WORKERS", 6), \
             patch.object(core, "fetch_public_content", side_effect=fake_fetch):
            enriched, metrics = core.enrich_with_content(results)
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 0.45)
        self.assertEqual(metrics["pages_fetched"], 6)
        self.assertEqual(
            [item["extracted_content"] for item in enriched],
            [f"https://example.com/{i}" for i in range(6)],
        )

    def test_phase2a_connectors_overlap(self):
        profile = {
            "full_name": "Test User",
            "email": "test@example.com",
            "username": "testuser",
            "phone": "",
            "context_terms": [],
        }

        def slow_web(*args, **kwargs):
            time.sleep(0.14)
            return ([{"source": "Tavily", "url": "https://a", "title": "a"}], {
                "provider": "tavily", "api_requests": 1, "cache_hits": 0, "warning": None
            })

        def slow_youtube(*args, **kwargs):
            time.sleep(0.14)
            return ([{"source": "YouTube", "url": "https://b", "title": "b"}], {
                "api_requests": 1, "cache_hits": 0
            })

        def slow_github(*args, **kwargs):
            time.sleep(0.14)
            return ([{"source": "GitHub", "url": "https://c", "title": "c"}], {
                "api_requests": 1, "cache_hits": 0
            })

        started = time.perf_counter()
        with patch.object(core, "choose_web_provider", return_value="tavily"), \
             patch.object(core, "generate_web_query_plan", return_value=[{
                 "purpose": "test", "query": "q", "includes_email": False
             }]), \
             patch.object(core, "generate_youtube_query", return_value="yt"), \
             patch.object(p2a, "build_targeted_profile_queries", return_value=[]), \
             patch.object(p2a, "cached_broad_web_search", side_effect=slow_web), \
             patch.object(p2a, "cached_youtube_search", side_effect=slow_youtube), \
             patch.object(p2a, "cached_github_lookup", side_effect=slow_github), \
             patch.object(core, "dedupe_results", side_effect=lambda x: x), \
             patch.object(core, "enrich_with_content", side_effect=lambda x: (x, {})), \
             patch.object(p2a, "PHASE2_CONNECTOR_WORKERS", 3):
            raw = p2a.create_raw_scan(profile)
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 0.38)
        self.assertEqual(raw["raw_results_count"], 3)
        self.assertEqual(
            [r["connector"] for r in raw["executed_queries"]],
            ["broad_web", "youtube", "github"],
        )

    def test_visual_queries_overlap_but_keep_plan_order(self):
        plan = [
            {"query": f"q{i}", "anchor_type": "name", "context_term": ""}
            for i in range(6)
        ]

        def slow_image_search(query, **kwargs):
            time.sleep(0.10)
            return ([{"image_url": f"https://img/{query}.jpg", "description": "face"}], {
                "api_requests": 1, "cache_hits": 0, "warning": None
            })

        started = time.perf_counter()
        with patch.object(visual, "build_independent_visual_query_plan", return_value=plan), \
             patch.object(core, "search_tavily_image_candidates", side_effect=slow_image_search), \
             patch.object(visual, "VISUAL_DISCOVERY_QUERY_WORKERS", 3):
            result = visual.discover_independent_visual_candidates({}, allow_network=True)
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 0.48)
        self.assertEqual([x["query"] for x in result["query_log"]], [f"q{i}" for i in range(6)])
        self.assertEqual(result["filtered_candidate_count"], 6)

    def test_breach_providers_overlap(self):
        def slow_xon(email):
            time.sleep(0.13)
            return {"provider": "XposedOrNot", "status": "success", "breaches": []}

        def slow_hibp(email, api_key, user_agent):
            time.sleep(0.13)
            return {"provider": "HIBP", "status": "success", "breaches": []}

        started = time.perf_counter()
        with patch.object(p2b, "configured_provider_names", return_value=(["xposedornot", "hibp"], [])), \
             patch.object(p2b, "xposedornot_breach_lookup", side_effect=slow_xon), \
             patch.object(p2b, "hibp_breach_lookup", side_effect=slow_hibp), \
             patch.object(p2b, "env_bool", return_value=False):
            results, _warnings, statuses = p2b.run_breach_providers("x@example.com")
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 0.30)
        self.assertEqual(len(results), 2)
        self.assertEqual(statuses["XposedOrNot"], "success")
        self.assertEqual(statuses["HIBP"], "success")

    def test_top_level_phase2_overlaps_2a_2c_and_breach_lookup(self):
        profile = {
            "full_name": "Test User",
            "email": "test@example.com",
            "username": "",
            "phone": "",
            "context_terms": [],
        }

        def fake_2a(*args, **kwargs):
            time.sleep(0.22)
            return {"analysis_report": {"results": []}, "warnings": []}

        def fake_compact(result):
            return {"status": "success", "summary": {}}

        def fake_2c(*args, **kwargs):
            time.sleep(0.22)
            return {"status": "success", "summary": {}, "warnings": [], "errors": []}

        def fake_breach(email):
            time.sleep(0.22)
            return ([], [], {})

        def fake_2b(*args, **kwargs):
            self.assertIsNotNone(kwargs.get("prefetched_breach_bundle"))
            return {"status": "success", "summary": {}, "warnings": [], "errors": []}

        started = time.perf_counter()
        with patch.object(runner.layer2a, "run_layer1", side_effect=fake_2a), \
             patch.object(runner.layer2a, "compact_layer1_for_aggregation", side_effect=fake_compact), \
             patch.object(runner.layer2c, "run_layer3", side_effect=fake_2c), \
             patch.object(runner.layer2c, "save_layer3_report", return_value="x"), \
             patch.object(runner.layer2b, "run_breach_providers", side_effect=fake_breach), \
             patch.object(runner.layer2b, "run_layer2", side_effect=fake_2b), \
             patch.object(runner.layer2b, "save_layer2_report", return_value="x"):
            report = runner.run_all(
                profile,
                consent_breach_lookup=True,
                consent_local_audit=True,
            )
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 0.48)
        self.assertEqual(report["collection_status"]["phase_2A"], "success")
        self.assertIn("phase_2_total_seconds", report["performance_metrics"])


if __name__ == "__main__":
    unittest.main()
