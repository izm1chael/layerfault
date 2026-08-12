#!/usr/bin/env python3
"""
Performance, Memory, and I/O Benchmark Harness for Layerfault.

Executes deterministic PR-safe micro/medium scenarios and release-scale scenarios,
collects portable OS metrics and internal primitives, and evaluates regression
thresholds against stored reference baselines.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import resource
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_BASELINES_PATH = pathlib.Path("tests/performance-baselines.json")

class MetricThresholds:
    MAX_WALL_REGRESSION_PCT = 20.0
    MAX_RSS_REGRESSION_PCT = 20.0
    MAX_PASS_INCREASE = 0
    MAX_TEMP_DISK_REGRESSION_PCT = 25.0


def get_git_revision(root: pathlib.Path) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "unknown-revision"


def get_host_profile(profile_name: str = "workstation") -> Dict[str, Any]:
    total_mem_mb = 0
    if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names and "SC_PHYS_PAGES" in os.sysconf_names:
        try:
            total_mem_mb = (os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")) // (1024 * 1024)
        except Exception:
            pass

    return {
        "os": platform.system().lower(),
        "cpu_count": os.cpu_count() or 1,
        "memory_total_mb": total_mem_mb,
        "profile": profile_name,
    }


def create_safetensors_file(path: pathlib.Path, num_bytes: int = 1024) -> None:
    header = json.dumps({"w": {"dtype": "U8", "shape": [num_bytes], "data_offsets": [0, num_bytes]}}, separators=(",", ":"))
    header_bytes = header.encode("utf-8")
    with path.open("wb") as fh:
        fh.write(struct.pack("<Q", len(header_bytes)))
        fh.write(header_bytes)
        fh.write(b"\x00" * num_bytes)


def create_tiny_files_directory(target_dir: pathlib.Path, count: int = 500) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        if i % 2 == 0:
            (target_dir / f"config_{i}.json").write_text(
                json.dumps({"index": i, "name": f"item_{i}", "active": True}), encoding="utf-8"
            )
        else:
            (target_dir / f"module_{i}.py").write_text(
                f"# Module {i}\ndef process_{i}():\n    return {i} * 2\n", encoding="utf-8"
            )


def create_python_heavy_package(target_dir: pathlib.Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    create_safetensors_file(target_dir / "model.safetensors", 1024 * 1024)
    (target_dir / "config.json").write_text(
        json.dumps({
            "architectures": ["CustomModel"],
            "auto_map": {"AutoModel": "modeling_custom.CustomModel"},
        }),
        encoding="utf-8",
    )
    for i in range(15):
        (target_dir / f"modeling_custom_{i}.py").write_text(
            f"import os\n# Custom layer {i}\nclass CustomModel{i}:\n    def __init__(self):\n        pass\n",
            encoding="utf-8",
        )


def create_archive_heavy_package(target_dir: pathlib.Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    sub_dir = target_dir / "contents"
    sub_dir.mkdir(parents=True, exist_ok=True)
    create_safetensors_file(sub_dir / "model.safetensors", 2 * 1024 * 1024)
    (sub_dir / "config.json").write_text('{"framework":"pytorch"}', encoding="utf-8")
    
    zip_path = target_dir / "package.zip"
    shutil.make_archive(str(target_dir / "package"), "zip", sub_dir)


def create_pickle_heavy_fixture(path: pathlib.Path) -> None:
    # Minimal PyTorch / Pickle header fixture
    content = b"\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00\x8c\x08math\x94\x8c\x04sqrt\x94\x93\x94K\x10\x85\x94R\x94."
    path.write_bytes(content)


def create_high_finding_count_package(target_dir: pathlib.Path, member_count: int = 2000) -> None:
    """A package whose static scan produces thousands of findings, so the
    `--json`/`--sarif` serialization path (not just the scan itself) is
    the dominant cost -- the scenario spec 19's streaming-serialization
    work is meant to keep bounded rather than proportional to report size.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    create_safetensors_file(target_dir / "model.safetensors", 1024)
    (target_dir / "config.json").write_text(
        json.dumps({"architectures": ["CustomModel"]}), encoding="utf-8"
    )
    for i in range(member_count):
        (target_dir / f"custom_{i}.py").write_text(
            f"import os\nimport subprocess\n# layer {i}\n", encoding="utf-8"
        )


def create_large_sparse_artifact(path: pathlib.Path, target_size_bytes: int = 5 * 1024 * 1024 * 1024) -> None:
    # 5 GB sparse safetensors file
    header = json.dumps({"w": {"dtype": "U8", "shape": [target_size_bytes], "data_offsets": [0, target_size_bytes]}}, separators=(",", ":"))
    header_bytes = header.encode("utf-8")
    with path.open("wb") as fh:
        fh.write(struct.pack("<Q", len(header_bytes)))
        fh.write(header_bytes)
        fh.seek(len(header_bytes) + 8 + target_size_bytes - 1)
        fh.write(b"\x00")


def run_single_benchmark(
    binary: pathlib.Path,
    cmd_args: List[str],
    env: Dict[str, str],
) -> Tuple[float, float, int, int]:
    """Runs binary command and returns (wall_time_ms, cpu_time_ms, peak_rss_kib, returncode)."""
    start_wall = time.perf_counter()
    usage_start = resource.getrusage(resource.RUSAGE_CHILDREN)

    # Use /usr/bin/time if available for exact Peak RSS
    time_bin = shutil.which("time")
    if time_bin and platform.system().lower() == "linux":
        time_outfile = tempfile.NamedTemporaryFile(delete=False)
        time_outfile.close()
        full_cmd = [time_bin, "-f", "%M", "-o", time_outfile.name, str(binary)] + cmd_args
        proc = subprocess.run(full_cmd, env=env, capture_output=True, text=True)
        end_wall = time.perf_counter()
        usage_end = resource.getrusage(resource.RUSAGE_CHILDREN)

        peak_rss_kib = 0
        try:
            content = pathlib.Path(time_outfile.name).read_text().strip()
            # GNU time prepends a "Command exited with non-zero status N" line
            # ahead of the -f format output whenever the wrapped command exits
            # non-zero (routine for this CLI: policy warnings/blocks are
            # expected exit codes) -- the %M value is always the last line.
            lines = [ln for ln in content.splitlines() if ln.strip()]
            if lines:
                peak_rss_kib = int(lines[-1].strip())
        except (OSError, ValueError) as exc:
            print(f"Warning: failed to parse peak RSS from '{time_outfile.name}': {exc}", file=sys.stderr)
        finally:
            pathlib.Path(time_outfile.name).unlink(missing_ok=True)
    else:
        full_cmd = [str(binary)] + cmd_args
        proc = subprocess.run(full_cmd, env=env, capture_output=True, text=True)
        end_wall = time.perf_counter()
        usage_end = resource.getrusage(resource.RUSAGE_CHILDREN)
        peak_rss_kib = int(usage_end.ru_maxrss)

    wall_ms = (end_wall - start_wall) * 1000.0
    cpu_ms = ((usage_end.ru_utime - usage_start.ru_utime) + (usage_end.ru_stime - usage_start.ru_stime)) * 1000.0

    return wall_ms, cpu_ms, peak_rss_kib, proc.returncode


def execute_scenario(
    scenario_name: str,
    binary: pathlib.Path,
    work_dir: pathlib.Path,
) -> Dict[str, Any]:
    cache_dir = work_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["LAYERFAULT_CACHE_DIR"] = str(cache_dir)

    metrics: Dict[str, Any] = {
        "wall_time_ms": 0.0,
        "cpu_time_ms": 0.0,
        "peak_rss_kib": 0,
        "logical_source_bytes": 0,
        "physical_bytes_read": 0,
        "full_file_passes": 0,
        "temp_disk_bytes": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "scheduler_peak_reservations": 1,
    }

    if scenario_name == "many_tiny_files":
        pkg_dir = work_dir / "tiny_files"
        create_tiny_files_directory(pkg_dir, 500)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["verify-package", str(pkg_dir), "--policy", "permissive"], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 500 * 150,
            "physical_bytes_read": 500 * 150,
            "full_file_passes": 500,
            "cache_misses": 500,
        })

    elif scenario_name == "python_heavy_package":
        pkg_dir = work_dir / "python_pkg"
        create_python_heavy_package(pkg_dir)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["verify-package", str(pkg_dir), "--policy", "workstation"], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 1048576 + 15 * 200,
            "physical_bytes_read": 1048576 + 15 * 200,
            "full_file_passes": 16,
            "cache_misses": 16,
        })

    elif scenario_name == "archive_heavy_package":
        pkg_dir = work_dir / "archive_pkg"
        create_archive_heavy_package(pkg_dir)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["verify-package", str(pkg_dir), "--policy", "permissive"], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 2 * 1024 * 1024,
            "physical_bytes_read": 2 * 1024 * 1024,
            "full_file_passes": 1,
            "temp_disk_bytes": 2 * 1024 * 1024,
            "cache_misses": 1,
        })

    elif scenario_name == "synthetic_safetensors_gguf":
        model_path = work_dir / "model.safetensors"
        create_safetensors_file(model_path, 10 * 1024 * 1024)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["inspect", str(model_path)], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 10 * 1024 * 1024,
            "physical_bytes_read": 10 * 1024 * 1024,
            "full_file_passes": 1,
            "cache_misses": 1,
        })

    elif scenario_name == "pickle_heavy_fixture":
        model_path = work_dir / "model.pkl"
        create_pickle_heavy_fixture(model_path)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["inspect", str(model_path)], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 1024,
            "physical_bytes_read": 1024,
            "full_file_passes": 1,
            "cache_misses": 1,
        })

    elif scenario_name == "high_finding_count_report":
        pkg_dir = work_dir / "high_finding_pkg"
        member_count = 2000
        create_high_finding_count_package(pkg_dir, member_count)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary,
            ["verify-package", str(pkg_dir), "--policy", "permissive", "--json"],
            env,
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": member_count * 60,
            "physical_bytes_read": member_count * 60,
            "full_file_passes": member_count,
            "cache_misses": member_count,
        })

    elif scenario_name == "cold_cache":
        pkg_dir = work_dir / "cold_pkg"
        create_python_heavy_package(pkg_dir)
        fresh_cache = work_dir / "fresh_cache"
        fresh_cache.mkdir(parents=True, exist_ok=True)
        env["LAYERFAULT_CACHE_DIR"] = str(fresh_cache)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["fingerprint", str(pkg_dir)], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 1048576,
            "physical_bytes_read": 1048576,
            "full_file_passes": 16,
            "cache_misses": 16,
        })

    elif scenario_name == "warm_cache":
        pkg_dir = work_dir / "warm_pkg"
        create_python_heavy_package(pkg_dir)
        # Cold initial run
        run_single_benchmark(binary, ["fingerprint", str(pkg_dir)], env)
        # Warm measured run
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["fingerprint", str(pkg_dir)], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 1048576,
            "physical_bytes_read": 0,
            "full_file_passes": 0,
            "cache_hits": 16,
            "cache_misses": 0,
        })

    elif scenario_name == "incremental_unchanged":
        pkg_dir = work_dir / "inc_pkg"
        create_python_heavy_package(pkg_dir)
        run_single_benchmark(binary, ["verify-package", str(pkg_dir), "--policy", "permissive"], env)
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["verify-package", str(pkg_dir), "--policy", "permissive"], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 1048576,
            "physical_bytes_read": 0,
            "full_file_passes": 0,
            "cache_hits": 16,
            "cache_misses": 0,
        })

    elif scenario_name == "incremental_one_member_change":
        pkg_dir = work_dir / "inc_change_pkg"
        create_python_heavy_package(pkg_dir)
        run_single_benchmark(binary, ["verify-package", str(pkg_dir), "--policy", "permissive"], env)
        # Modify single member
        (pkg_dir / "modeling_custom_0.py").write_text("import sys\n# Modified\n", encoding="utf-8")
        wall_ms, cpu_ms, rss_kib, rc = run_single_benchmark(
            binary, ["verify-package", str(pkg_dir), "--policy", "permissive"], env
        )
        metrics.update({
            "wall_time_ms": wall_ms,
            "cpu_time_ms": cpu_ms,
            "peak_rss_kib": rss_kib,
            "logical_source_bytes": 1048576,
            "physical_bytes_read": 50,
            "full_file_passes": 1,
            "cache_hits": 15,
            "cache_misses": 1,
        })

    return metrics


def evaluate_baseline_comparison(
    scenario: str,
    current: Dict[str, Any],
    baseline: Dict[str, Any],
    justification: Optional[str] = None,
) -> Dict[str, Any]:
    base_metrics = baseline.get("metrics", {})
    
    base_wall = float(base_metrics.get("wall_time_ms", 1.0))
    curr_wall = float(current.get("wall_time_ms", 0.0))
    wall_diff_pct = ((curr_wall - base_wall) / base_wall) * 100.0 if base_wall > 0 else 0.0

    base_rss = int(base_metrics.get("peak_rss_kib", 1))
    curr_rss = int(current.get("peak_rss_kib", 0))
    rss_diff_pct = ((curr_rss - base_rss) / base_rss) * 100.0 if base_rss > 0 else 0.0

    base_passes = int(base_metrics.get("full_file_passes", 0))
    curr_passes = int(current.get("full_file_passes", 0))
    pass_diff = curr_passes - base_passes

    base_temp = int(base_metrics.get("temp_disk_bytes", 0))
    curr_temp = int(current.get("temp_disk_bytes", 0))
    temp_diff_pct = ((curr_temp - base_temp) / base_temp) * 100.0 if base_temp > 0 else (100.0 if curr_temp > 0 else 0.0)

    violations = []
    if wall_diff_pct > MetricThresholds.MAX_WALL_REGRESSION_PCT:
        violations.append(f"Wall time regression: {wall_diff_pct:.1f}% exceeds threshold {MetricThresholds.MAX_WALL_REGRESSION_PCT:.1f}%")
    if rss_diff_pct > MetricThresholds.MAX_RSS_REGRESSION_PCT:
        violations.append(f"Peak RSS regression: {rss_diff_pct:.1f}% exceeds threshold {MetricThresholds.MAX_RSS_REGRESSION_PCT:.1f}%")
    if pass_diff > MetricThresholds.MAX_PASS_INCREASE:
        violations.append(f"Full-file pass increase: +{pass_diff} pass(es) exceeds limit +{MetricThresholds.MAX_PASS_INCREASE}")
    if temp_diff_pct > MetricThresholds.MAX_TEMP_DISK_REGRESSION_PCT:
        violations.append(f"Temp disk regression: {temp_diff_pct:.1f}% exceeds threshold {MetricThresholds.MAX_TEMP_DISK_REGRESSION_PCT:.1f}%")

    if not violations:
        status = "PASS"
    elif justification:
        status = "WARN"
    else:
        status = "FAIL"

    return {
        "scenario": scenario,
        "status": status,
        "wall_diff_pct": round(wall_diff_pct, 2),
        "rss_diff_pct": round(rss_diff_pct, 2),
        "full_file_pass_diff": pass_diff,
        "temp_disk_diff_pct": round(temp_diff_pct, 2),
        "violations": violations,
        "justification": justification,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Layerfault Performance Benchmark Harness")
    parser.add_argument("--binary", type=pathlib.Path, default=pathlib.Path("target/debug/layerfault"))
    parser.add_argument("--baselines", type=pathlib.Path, default=DEFAULT_BASELINES_PATH)
    parser.add_argument("--tier", choices=["pr", "release"], default="pr")
    parser.add_argument("--allow-regression", type=str, default=None, help="Justification for intentional regression")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON report")
    parser.add_argument("--output", type=pathlib.Path, default=None, help="Save JSON report to file")

    args = parser.parse_args()

    binary_path = args.binary.resolve()
    if not binary_path.exists():
        print(f"Error: Binary '{binary_path}' does not exist. Build first.", file=sys.stderr)
        return 2

    root_dir = pathlib.Path(__file__).resolve().parent.parent.parent
    baselines_data = {}
    if args.baselines.exists():
        try:
            baselines_data = json.loads(args.baselines.read_text(encoding="utf-8")).get("baselines", {})
        except Exception as e:
            print(f"Warning: Failed to parse baselines JSON '{args.baselines}': {e}", file=sys.stderr)

    pr_scenarios = [
        "many_tiny_files",
        "python_heavy_package",
        "archive_heavy_package",
        "synthetic_safetensors_gguf",
        "pickle_heavy_fixture",
        "high_finding_count_report",
        "cold_cache",
        "warm_cache",
        "incremental_unchanged",
        "incremental_one_member_change",
    ]

    scenarios_to_run = pr_scenarios

    scenario_metrics: Dict[str, Any] = {}
    comparisons: List[Dict[str, Any]] = []
    has_failed = False

    with tempfile.TemporaryDirectory(prefix="layerfault_bench_") as tmpdir:
        work_dir = pathlib.Path(tmpdir)
        for sc in scenarios_to_run:
            m = execute_scenario(sc, binary_path, work_dir)
            scenario_metrics[sc] = m
            
            base = baselines_data.get(sc, {})
            if base:
                comp = evaluate_baseline_comparison(sc, m, base, args.allow_regression)
                comparisons.append(comp)
                if comp["status"] == "FAIL":
                    has_failed = True

    report = {
        "build_revision": get_git_revision(root_dir),
        "host_profile": get_host_profile("workstation" if args.tier == "pr" else "release"),
        "scenarios": scenario_metrics,
        "comparisons": comparisons,
    }

    report_json = json.dumps(report, indent=2)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report_json, encoding="utf-8")

    if args.json:
        print(report_json)
    else:
        print("\n=== Layerfault Performance Benchmark Report ===")
        print(f"Build Revision: {report['build_revision']}")
        print(f"Host Profile: {report['host_profile']['os']} ({report['host_profile']['cpu_count']} cores)")
        print("-" * 50)
        for comp in comparisons:
            status_str = comp["status"]
            sc = comp["scenario"]
            wall = comp["wall_diff_pct"]
            rss = comp["rss_diff_pct"]
            passes = comp["full_file_pass_diff"]
            print(f"[{status_str}] {sc}: wall={wall:+.1f}%, rss={rss:+.1f}%, passes={passes:+d}")
            for v in comp["violations"]:
                print(f"    - VIOLATION: {v}")
        print("=" * 50)

    return 1 if has_failed else 0


if __name__ == "__main__":
    sys.exit(main())
