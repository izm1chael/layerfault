#!/usr/bin/env python3
"""
Unit tests for the performance benchmark harness and PR regression gate logic.
"""
from __future__ import annotations

import json
import pathlib
import sys
import unittest

# Import harness module functions
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from benchmark_harness import evaluate_baseline_comparison, get_host_profile


class TestPerformanceGateLogic(unittest.TestCase):

    def test_baseline_comparison_pass(self):
        baseline = {
            "metrics": {
                "wall_time_ms": 100.0,
                "peak_rss_kib": 10000,
                "full_file_passes": 1,
                "temp_disk_bytes": 0,
            }
        }
        current = {
            "wall_time_ms": 105.0,  # +5%
            "peak_rss_kib": 10500,  # +5%
            "full_file_passes": 1,
            "temp_disk_bytes": 0,
        }

        eval_res = evaluate_baseline_comparison("test_pass", current, baseline)
        self.assertEqual(eval_res["status"], "PASS")
        self.assertEqual(len(eval_res["violations"]), 0)
        self.assertAlmostEqual(eval_res["wall_diff_pct"], 5.0)

    def test_baseline_comparison_wall_regression_fail(self):
        baseline = {
            "metrics": {
                "wall_time_ms": 100.0,
                "peak_rss_kib": 10000,
                "full_file_passes": 1,
                "temp_disk_bytes": 0,
            }
        }
        current = {
            "wall_time_ms": 130.0,  # +30% (exceeds 20%)
            "peak_rss_kib": 10000,
            "full_file_passes": 1,
            "temp_disk_bytes": 0,
        }

        eval_res = evaluate_baseline_comparison("test_fail_wall", current, baseline)
        self.assertEqual(eval_res["status"], "FAIL")
        self.assertEqual(len(eval_res["violations"]), 1)
        self.assertIn("Wall time regression", eval_res["violations"][0])

    def test_baseline_comparison_pass_increase_fail(self):
        baseline = {
            "metrics": {
                "wall_time_ms": 100.0,
                "peak_rss_kib": 10000,
                "full_file_passes": 1,
                "temp_disk_bytes": 0,
            }
        }
        current = {
            "wall_time_ms": 100.0,
            "peak_rss_kib": 10000,
            "full_file_passes": 2,  # +1 pass (exceeds 0)
            "temp_disk_bytes": 0,
        }

        eval_res = evaluate_baseline_comparison("test_fail_pass", current, baseline)
        self.assertEqual(eval_res["status"], "FAIL")
        self.assertEqual(len(eval_res["violations"]), 1)
        self.assertIn("Full-file pass increase", eval_res["violations"][0])

    def test_baseline_comparison_justified_override(self):
        baseline = {
            "metrics": {
                "wall_time_ms": 100.0,
                "peak_rss_kib": 10000,
                "full_file_passes": 1,
                "temp_disk_bytes": 0,
            }
        }
        current = {
            "wall_time_ms": 140.0,  # +40%
            "peak_rss_kib": 10000,
            "full_file_passes": 2,
            "temp_disk_bytes": 0,
        }

        eval_res = evaluate_baseline_comparison(
            "test_override",
            current,
            baseline,
            justification="Justified stronger security parser for deep scanning",
        )
        self.assertEqual(eval_res["status"], "WARN")
        self.assertEqual(len(eval_res["violations"]), 2)
        self.assertEqual(eval_res["justification"], "Justified stronger security parser for deep scanning")

    def test_host_profile_generation(self):
        profile = get_host_profile("workstation")
        self.assertIn("os", profile)
        self.assertIn("cpu_count", profile)
        self.assertGreaterEqual(profile["cpu_count"], 1)


if __name__ == "__main__":
    unittest.main()
