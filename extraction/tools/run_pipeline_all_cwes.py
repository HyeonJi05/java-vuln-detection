#!/usr/bin/env python3
"""Run the 4-stage source/sink extraction pipeline over all SARD CWEs
(Java or C/C++ Juliet, selected via --language).

Folder/file naming matches the manual run (without the '-my' suffix):
    artifacts/pipeline-runs/{language}-cwe{N}-source-sink/
        {language}-cwe{N}-manifest.xml
        01_manifest/manifest_with_comments.xml
        02b_flow/manifest_with_testcase_flows.xml
        02b_flow/summary.json
        02b_flow/epic002/source_sink_classified.xml
        02b_flow/epic002/source_sink_exceptions.xml
        02b_flow/epic002/summary.json

- By default every CWE in the dataset is processed. Use --skip to exclude
  specific CWEs, or --only to restrict to a subset.
- If one CWE fails, the batch does NOT stop; it records and continues.
- Final classified XMLs are gathered into --output-dir with a cwe{N}_ prefix
  (default depends on --language: java_sard_source_sink/ or c_sard_source_sink/).
- Per-CWE status and problems are written to --log-dir as CSV/TXT logs.

Runs on any OS (Linux/macOS/Windows) as long as python + the pipeline deps
(typer, tree-sitter==0.21.3, tree_sitter_languages==1.10.2) are installed.

Usage (from juliet-playground root, venv active):
    python tools/run_pipeline_all_cwes.py                          # all Java CWEs
    python tools/run_pipeline_all_cwes.py --language c              # all C CWEs
    python tools/run_pipeline_all_cwes.py --only 190 476            # just these
    python tools/run_pipeline_all_cwes.py --skip 113                # all except 113
"""
from __future__ import annotations

import argparse
import csv
import datetime
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# --- pipeline stage scripts (relative to repo root) ---
# Resolve stage-script paths relative to this file's project root
# (extraction/tools/run_pipeline_all_cwes.py -> project root is two levels up)
_ROOT = Path(__file__).resolve().parent.parent   # .../extraction
STAGE1 = str(_ROOT / "tools/generate_juliet_manifest.py")
STAGE2 = str(_ROOT / "experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py")
STAGE3 = str(_ROOT / "experiments/epic001c_testcase_flow_partition/scripts/add_flow_tags_to_testcase.py")
STAGE4 = str(_ROOT / "experiments/epic002/classify_flow_comments_by_function_name.py")


def run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr)."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def discover_cwes(dataset_root: Path, language: str) -> list[int]:
    cwes = []
    if language == "java":
        for d in dataset_root.glob("juliet-cwe*"):
            m = re.match(r"juliet-cwe(\d+)", d.name)
            if d.is_dir() and m:
                cwes.append(int(m.group(1)))
    else:
        # C/C++ Juliet layout: <root>/testcases/CWE{N}_{Name}/
        for d in (dataset_root / "testcases").glob("CWE*_*"):
            m = re.match(r"CWE(\d+)_", d.name)
            if d.is_dir() and m:
                cwes.append(int(m.group(1)))
    return sorted(set(cwes))


def process_cwe(cwe: int, dataset_root: Path, run_root: Path, output_dir: Path, language: str):
    """Run the 4-stage pipeline for one CWE. Returns a result dict."""
    if language == "java":
        src = dataset_root / f"juliet-cwe{cwe}" / "src" / "main" / "java"
        stage2_source_root = src / "juliet"  # Java SARD keeps sources under .../java/juliet
        suffix_args = ["--suffix", ".java"]
    else:
        # C/C++: pass the whole dataset root (contains testcases/); --cwe filters per-CWE.
        src = dataset_root
        stage2_source_root = dataset_root
        suffix_args = ["--suffix", ".c", "--suffix", ".cpp"]

    result = {
        "cwe": cwe, "status": "ok", "flows": 0, "classified": 0,
        "missing": 0, "parse_fail": 0, "exceptions": 0, "note": "",
    }
    if not src.is_dir():
        result["status"] = "no-source-dir"
        return result

    run_dir = run_root / f"{language}-cwe{cwe}-source-sink"
    (run_dir / "01_manifest").mkdir(parents=True, exist_ok=True)
    (run_dir / "02b_flow" / "epic002").mkdir(parents=True, exist_ok=True)

    man = run_dir / f"{language}-cwe{cwe}-manifest.xml"
    com = run_dir / "01_manifest" / "manifest_with_comments.xml"
    flo = run_dir / "02b_flow" / "manifest_with_testcase_flows.xml"
    sj1 = run_dir / "02b_flow" / "summary.json"
    cls = run_dir / "02b_flow" / "epic002" / "source_sink_classified.xml"
    exc = run_dir / "02b_flow" / "epic002" / "source_sink_exceptions.xml"
    sj2 = run_dir / "02b_flow" / "epic002" / "summary.json"

    py = sys.executable  # use the same interpreter (venv-safe)
    fail_stage = 0
    o2 = ""
    try:
        c, _, e = run([py, STAGE1, "--source-root", str(src),
                       "--output-xml", str(man), "--cwe", str(cwe), *suffix_args])
        if c != 0:
            fail_stage, result["note"] = 1, e[-200:]

        if fail_stage == 0:
            c, o2, e = run([py, STAGE2, "--manifest", str(man),
                            "--source-root", str(stage2_source_root), "--output-xml", str(com)])
            if c != 0:
                fail_stage, result["note"] = 2, e[-200:]

        if fail_stage == 0:
            c, _, e = run([py, STAGE3, "--input-xml", str(com),
                           "--output-xml", str(flo), "--summary-json", str(sj1)])
            if c != 0:
                fail_stage, result["note"] = 3, e[-200:]

        if fail_stage == 0:
            c, _, e = run([py, STAGE4, "--manifest-xml", str(flo),
                           "--output-xml", str(cls), "--exceptions-xml", str(exc),
                           "--summary-json", str(sj2)])
            if c != 0:
                fail_stage, result["note"] = 4, e[-200:]
    except Exception as ex:  # any unexpected crash -> record, keep going
        fail_stage, result["note"] = -1, str(ex)[-200:]

    if fail_stage != 0:
        label = "EXCEPTION" if fail_stage == -1 else f"stage{fail_stage}"
        result["status"] = f"FAIL-{label}"
        return result

    # --- parse stage-4 summary for flow counts ---
    try:
        j2 = json.loads(sj2.read_text())
        result["flows"] = int(j2["counts"]["flows_total"])
        result["classified"] = int(j2["counts"]["classified_flows_total"])
    except Exception as ex:
        result["note"] += f" [sj2 parse err: {ex}]"

    # --- parse stage-2 stdout last line for missing/parse-fail ---
    try:
        last = o2.strip().splitlines()[-1]
        m = json.loads(last)
        result["missing"] = int(m.get("missing_files", 0))
        result["parse_fail"] = int(m.get("parse_failed_files", 0))
    except Exception:
        pass

    # --- count exception entries (classification failures) ---
    try:
        er = ET.parse(exc).getroot()
        result["exceptions"] = len(list(er))
    except Exception:
        pass

    # --- copy final XML to output folder with cwe{N}_ prefix ---
    if cls.exists():
        shutil.copy(cls, output_dir / f"cwe{cwe}_source_sink_classified.xml")
        if result["exceptions"] > 0:
            shutil.copy(exc, output_dir / f"cwe{cwe}_source_sink_exceptions.xml")

    # --- status flags ---
    if (result["flows"] != result["classified"] or result["missing"] > 0
            or result["parse_fail"] > 0 or result["exceptions"] > 0):
        result["status"] = "WARN"
    if result["flows"] == 0:
        result["status"] = "empty"  # CWE with no source/sink flows (not a failure)

    return result


def main():
    ap = argparse.ArgumentParser(description="Run source/sink pipeline over all CWEs.")
    ap.add_argument("--language", choices=("java", "c"), default="java",
                    help="Source language (default: java).")
    ap.add_argument("--dataset-root", default=None,
                    help="Default: juliet-java-test-suite (java) / juliet-test-suite-c (c)")
    ap.add_argument("--run-root", default="artifacts/pipeline-runs")
    ap.add_argument("--output-dir", default=None,
                    help="Default: java_sard_source_sink/source_sink_dataset (java) / "
                         "c_sard_source_sink/source_sink_dataset (c)")
    ap.add_argument("--log-dir", default=None,
                    help="Default: java_sard_source_sink/logs (java) / c_sard_source_sink/logs (c)")
    ap.add_argument("--skip", type=int, nargs="*", default=[],
                    help="CWE numbers to skip (default: none)")
    ap.add_argument("--only", type=int, nargs="*", default=None,
                    help="If set, run ONLY these CWE numbers")
    args = ap.parse_args()

    default_root = "juliet-java-test-suite" if args.language == "java" else "juliet-test-suite-c"
    default_out_base = "java_sard_source_sink" if args.language == "java" else "c_sard_source_sink"

    dataset_root = Path(args.dataset_root or default_root)
    run_root = Path(args.run_root)
    output_dir = Path(args.output_dir or f"{default_out_base}/source_sink_dataset")
    log_dir = Path(args.log_dir or f"{default_out_base}/logs")
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    cwes = discover_cwes(dataset_root, args.language)
    if args.only:
        cwes = [c for c in cwes if c in args.only]
    else:
        cwes = [c for c in cwes if c not in args.skip]

    print(f"Target CWEs: {len(cwes)}  (skipped: {args.skip if not args.only else 'n/a'})")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    progress_log = log_dir / f"batch_progress_{stamp}.txt"
    progress_log.write_text(f"batch start {stamp}\n")

    report, problems = [], []
    for cwe in cwes:
        r = process_cwe(cwe, dataset_root, run_root, output_dir, args.language)
        report.append(r)
        line = (f"CWE-{r['cwe']}  {r['status']}  flows={r['flows']} "
                f"classified={r['classified']} missing={r['missing']} exc={r['exceptions']}")
        print(line)
        with progress_log.open("a") as f:
            f.write(line + "\n")
        if r["status"].startswith("FAIL") or r["status"] == "WARN":
            problems.append(r)

    # --- write logs ---
    report_csv = log_dir / f"batch_report_{stamp}.csv"
    with report_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(report[0].keys()))
        w.writeheader()
        w.writerows(report)

    problem_csv = log_dir / f"batch_problems_{stamp}.csv"
    if problems:
        with problem_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(problems[0].keys()))
            w.writeheader()
            w.writerows(problems)
    else:
        problem_csv.write_text("no problems (all CWEs processed cleanly)\n")

    ok = sum(1 for r in report if r["status"] == "ok")
    empty = sum(1 for r in report if r["status"] == "empty")
    warn = sum(1 for r in report if r["status"] == "WARN")
    fail = sum(1 for r in report if r["status"].startswith("FAIL") or r["status"] == "no-source-dir")
    total_flows = sum(r["flows"] for r in report)

    language_label = {"java": "Java", "c": "C/C++"}[args.language]
    summary = (
        f"=== {language_label} SARD source/sink extraction batch summary ({stamp}) ===\n"
        f"Target CWEs:   {len(cwes)}\n"
        f"  ok:          {ok}\n"
        f"  empty:       {empty}   (no source/sink flows - not a failure)\n"
        f"  WARN:        {warn}    (flows != classified / missing / exceptions)\n"
        f"  FAIL:        {fail}\n"
        f"Total flows:   {total_flows}\n\n"
        f"Output XMLs:   {output_dir}\n"
        f"Full report:   {report_csv}\n"
        f"Problems only: {problem_csv}\n"
        f"Progress log:  {progress_log}\n"
    )
    (log_dir / f"batch_summary_{stamp}.txt").write_text(summary)
    print("\n" + summary)
    print(f"Done. Output folder: {output_dir}")


if __name__ == "__main__":
    main()