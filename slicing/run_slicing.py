#!/usr/bin/env python3
"""One-command slicing runner for the java-vuln-detection project.

Clone the repo, install the Python deps, install joern + JDK 17, then run:

    python3 run_slicing.py --per-cwe 5

This script prepares everything the team's slicing scripts need, WITHOUT the
manual setting.sh / .env editing:

  1. Locates joern (auto-detect, or --joern <path>). If missing, prints how to
     install it and exits (joern + JDK are the only manual prerequisites).
  2. Downloads the servlet API JAR into deps/ if absent (Maven Central).
  3. Builds the Juliet support JAR into deps/ if absent (uses the ROOT
     juliet-java-test-suite submodule, then cleans the build output so the
     submodule stays clean). No second juliet clone.
  4. Writes a throwaway .env pointing at all of the above and the ROOT juliet
     submodule, and hands it to cpg_builder.py (team code, unmodified).
  5. Filters the extraction XMLs, builds/reuses CPGs, and runs the optimized
     one-joern-session-per-CWE batch slicing.

Layout assumed (this file lives in slicing/):

    java-vuln-detection/
    |-- juliet-java-test-suite/      (submodule; source + gradlew)
    |-- java_sard_source_sink/       (extraction output; the XMLs)
    |   `-- source_sink_dataset/
    `-- slicing/
        |-- run_slicing.py           (this file)
        |-- cpg_builder.py           (team, unmodified)
        |-- flow_filter.py           (team, unmodified)
        |-- deps/                    (auto-created; gitignored)
        `-- script/
            |-- pdg_slice_batch.sc
            `-- run_pdg_slice_batch.sh
"""
from __future__ import annotations

import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (all relative to this file, so the folder can be moved freely)
# ---------------------------------------------------------------------------
SLICING_DIR = Path(__file__).resolve().parent
REPO_ROOT = SLICING_DIR.parent
JULIET_DIR = REPO_ROOT / "juliet-java-test-suite"
EXTRACTION_OUT = REPO_ROOT / "java_sard_source_sink" / "source_sink_dataset"

DEPS_DIR = SLICING_DIR / "deps"
OUTPUT_DIR = SLICING_DIR / "output"
FILTERED_DIR = OUTPUT_DIR / "filtered_source_sink_dataset"
CPG_DIR = OUTPUT_DIR / "CPG"

CPG_BUILDER = SLICING_DIR / "cpg_builder.py"
FLOW_FILTER = SLICING_DIR / "flow_filter.py"
RUN_SLICE_BATCH = SLICING_DIR / "script" / "run_pdg_slice_batch.sh"

SERVLET_JAR = DEPS_DIR / "javax.servlet-api-3.1.0.jar"
SERVLET_URL = (
    "https://repo1.maven.org/maven2/javax/servlet/"
    "javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar"
)
SUPPORT_JAR = DEPS_DIR / "juliet-support-only.jar"

# Common places joern's CLI dir may live
JOERN_CANDIDATES = [
    Path.home() / "bin" / "joern" / "joern-cli",
    Path.home() / "joern" / "joern-cli",
    Path("/opt/joern/joern-cli"),
]


def sh(cmd, **kw):
    """Run a command, streaming nothing; return (rc, combined_output)."""
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout + p.stderr


# ---------------------------------------------------------------------------
# Step 1: locate joern (auto-detect only; do not auto-install)
# ---------------------------------------------------------------------------
def find_joern(explicit: str | None) -> Path:
    if explicit:
        cli = Path(explicit).expanduser().resolve()
        if (cli / "joern-parse").is_file():
            return cli
        sys.exit(f"[joern] --joern path has no joern-parse: {cli}")

    # on PATH?
    which = shutil.which("joern-parse")
    if which:
        return Path(which).resolve().parent

    for cand in JOERN_CANDIDATES:
        if (cand / "joern-parse").is_file():
            return cand

    sys.exit(
        "[joern] joern not found.\n"
        "  Install it once, e.g.:\n"
        '    mkdir -p ~/joern && cd ~/joern\n'
        '    curl -L "https://github.com/joernio/joern/releases/latest/'
        'download/joern-install.sh" -o joern-install.sh\n'
        "    chmod u+x joern-install.sh && ./joern-install.sh --interactive\n"
        "  (Requires JDK 17: sudo apt install openjdk-17-jdk)\n"
        "  Then re-run, or pass --joern <path-to>/joern-cli"
    )


# ---------------------------------------------------------------------------
# Step 2: servlet JAR (download if missing)
# ---------------------------------------------------------------------------
def ensure_servlet_jar():
    if SERVLET_JAR.is_file() and SERVLET_JAR.stat().st_size > 1000:
        print(f"[servlet] present: {SERVLET_JAR.name}")
        return
    DEPS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[servlet] downloading from Maven Central ...")
    rc, out = sh(["curl", "-L", "-o", str(SERVLET_JAR), SERVLET_URL])
    if rc != 0 or not SERVLET_JAR.is_file():
        sys.exit(f"[servlet] download failed:\n{out}")
    print(f"[servlet] saved: {SERVLET_JAR} ({SERVLET_JAR.stat().st_size} bytes)")


# ---------------------------------------------------------------------------
# Step 3: support JAR (build from ROOT juliet if missing, then clean up)
# ---------------------------------------------------------------------------
def ensure_support_jar():
    if SUPPORT_JAR.is_file() and SUPPORT_JAR.stat().st_size > 1000:
        print(f"[support] present: {SUPPORT_JAR.name}")
        return
    if not JULIET_DIR.is_dir():
        sys.exit(
            f"[support] juliet submodule missing: {JULIET_DIR}\n"
            "  Run: git submodule update --init juliet-java-test-suite"
        )
    DEPS_DIR.mkdir(parents=True, exist_ok=True)
    gradlew = JULIET_DIR / "gradlew"
    if not gradlew.is_file():
        sys.exit(f"[support] gradlew not found in {JULIET_DIR}")

    print("[support] building juliet support classes (gradlew) ...")
    os.chmod(gradlew, 0o755)
    rc, out = sh(["./gradlew", ":support:classes"], cwd=str(JULIET_DIR))
    if rc != 0:
        sys.exit(f"[support] gradlew build failed:\n{out[-1500:]}")

    classes = JULIET_DIR / "juliet-support" / "build" / "classes" / "java" / "main"
    if not classes.is_dir():
        sys.exit(f"[support] compiled classes not found: {classes}")

    print("[support] packaging JAR ...")
    rc, out = sh(["jar", "--create", "--file", str(SUPPORT_JAR),
                  "-C", str(classes), "juliet"])
    if rc != 0 or not SUPPORT_JAR.is_file():
        sys.exit(f"[support] jar packaging failed:\n{out}")

    # keep the juliet submodule clean: remove gradle build output
    print("[support] cleaning juliet build output (keep submodule clean) ...")
    sh(["./gradlew", "clean"], cwd=str(JULIET_DIR))
    for junk in ("juliet-support/build", "support/build", "build", ".gradle"):
        p = JULIET_DIR / junk
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
    print(f"[support] saved: {SUPPORT_JAR} ({SUPPORT_JAR.stat().st_size} bytes)")


# ---------------------------------------------------------------------------
# Step 4: write a throwaway .env for cpg_builder.py (team code, unmodified)
# ---------------------------------------------------------------------------
def write_env(joern_cli: Path) -> Path:
    env_path = SLICING_DIR / ".env"
    env_path.write_text(
        f"JULIET_DIR={JULIET_DIR.resolve()}\n"
        f"JOERN_PARSE={(joern_cli / 'joern-parse').resolve()}\n"
        f"JOERN={(joern_cli / 'joern').resolve()}\n"
        f"SUPPORT_JAR={SUPPORT_JAR.resolve()}\n"
        f"SERVLET_JAR={SERVLET_JAR.resolve()}\n"
    )
    print(f"[env] wrote {env_path}")
    return env_path


# ---------------------------------------------------------------------------
# Step 5: filter -> build/reuse CPGs -> one joern session per CWE
# ---------------------------------------------------------------------------
def cwe_num(path: Path):
    m = re.match(r"cwe(\d+)_", path.name)
    return int(m.group(1)) if m else None


def filter_xmls(only, refilter):
    if not EXTRACTION_OUT.is_dir():
        sys.exit(
            f"[filter] extraction output not found: {EXTRACTION_OUT}\n"
            "  Run the extraction pipeline first (produces the source/sink XMLs)."
        )
    # Reuse existing filtered XMLs unless --refilter is given.
    existing = list(FILTERED_DIR.glob("cwe*_source_sink_classified.xml"))
    if existing and not refilter:
        print(f"[filter] reusing {len(existing)} filtered XML(s) "
              f"(use --refilter to redo)")
        return
    FILTERED_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[filter] filtering XMLs from {EXTRACTION_OUT} ...")
    rc, out = sh([sys.executable, str(FLOW_FILTER), str(EXTRACTION_OUT),
                  "--output-dir", str(FILTERED_DIR.relative_to(SLICING_DIR))])
    # flow_filter's --output-dir is relative to its own dir; fall back to abs if needed
    if rc != 0:
        rc, out = sh([sys.executable, str(FLOW_FILTER), str(EXTRACTION_OUT)])
    print(out.strip().splitlines()[-1] if out.strip() else "[filter] done")


def run_batch(env_path, per_cwe, only, force, sample, seed, result_dir):
    xmls = sorted(FILTERED_DIR.glob("cwe*_source_sink_classified.xml"))
    if only:
        xmls = [x for x in xmls if cwe_num(x) in only]
    if not xmls:
        sys.exit(f"[batch] no filtered XMLs in {FILTERED_DIR}")

    jobs_dir = result_dir / "jobs"
    result_dir.mkdir(parents=True, exist_ok=True)
    jobs_dir.mkdir(parents=True, exist_ok=True)
    per_cwe_label = "all" if per_cwe <= 0 else str(per_cwe)
    mode = f"random(seed={seed})" if sample else "first"
    print(f"[batch] {len(xmls)} CWE(s), per-cwe={per_cwe_label}, select={mode}")
    print(f"[batch] results -> {result_dir}\n")

    rng = random.Random(seed) if sample else None

    total_cwe = total_flows = total_fail = 0
    for xml_path in xmls:
        cwe = cwe_num(xml_path)
        print(f"===== CWE-{cwe} =====")
        try:
            root = ET.parse(xml_path).getroot()
        except Exception as e:
            print(f"  [skip] parse error: {e}")
            continue
        all_tc = root.findall(".//testcase")
        if per_cwe <= 0:
            testcases = all_tc                 # all testcases
        elif sample:
            # random N (without replacement); reproducible via --seed
            k = min(per_cwe, len(all_tc))
            testcases = rng.sample(all_tc, k)
        else:
            testcases = all_tc[:per_cwe]        # first N in XML order
        job_lines = []
        for tc in testcases:
            idx = tc.get("testcase_index")
            cpg = CPG_DIR / f"cwe{cwe}_cpg" / f"cwe{cwe}-{idx}-cpg-resolved.bin"
            if not (cpg.exists() and not force):
                cmd = [sys.executable, str(CPG_BUILDER), str(xml_path),
                       "--env-file", str(env_path),
                       "--output-dir", str(CPG_DIR / f"cwe{cwe}_cpg"),
                       "--testcase-index", str(idx)]
                if force:
                    cmd.append("--force")
                rc, out = sh(cmd)
                if rc != 0 or not cpg.exists():
                    print(f"  [tc{idx}] CPG build FAILED")
                    total_fail += 1
                    continue
            for flow in tc.findall(".//flow"):
                fidx = flow.get("flow_index", "?")
                src = sink = None
                for node in flow:
                    if node.get("role") == "source":
                        src = (node.get("file"), node.get("line"))
                    elif node.get("role") == "sink":
                        sink = (node.get("file"), node.get("line"))
                if not src or not sink or None in src or None in sink:
                    continue
                job_lines.append(
                    f"{cpg.resolve()}\ttc{idx}_flow{fidx}\t"
                    f"{src[0]}\t{src[1]}\t{sink[0]}\t{sink[1]}"
                )
        if not job_lines:
            print("  [skip] no valid flows")
            continue
        jobs_file = jobs_dir / f"cwe{cwe}_jobs.tsv"
        jobs_file.write_text("\n".join(job_lines) + "\n")
        log_path = result_dir / f"cwe{cwe}.txt"
        rc, out = sh(["bash", str(RUN_SLICE_BATCH), str(jobs_file)])
        with log_path.open("w") as fh:
            fh.write(f"# CWE-{cwe}: {len(job_lines)} flow(s), one joern session\n\n")
            fh.write(out)
        if rc == 0:
            total_cwe += 1
            total_flows += len(job_lines)
            print(f"  CWE-{cwe} done: {len(job_lines)} flows.")
        else:
            total_fail += 1
            print(f"  [CWE-{cwe}] joern rc={rc}")

    print(f"\n=== Done: {total_cwe} CWEs, {total_flows} flows, {total_fail} failures ===")
    print(f"Results: {result_dir}")


def main():
    ap = argparse.ArgumentParser(description="One-command Juliet slicing runner.")
    ap.add_argument("--joern", default=None,
                    help="Path to joern-cli dir (auto-detected if omitted)")
    ap.add_argument("--per-cwe", type=int, default=5,
                    help="Process only the first N testcases per CWE "
                         "(0 or negative = all testcases)")
    ap.add_argument("--only", type=int, nargs="*", default=None)
    ap.add_argument("--force", action="store_true",
                    help="Rebuild CPGs even if present")
    ap.add_argument("--sample", action="store_true",
                    help="Pick testcases randomly instead of the first N "
                         "(ignored when --per-cwe 0)")
    ap.add_argument("--seed", type=int, default=0,
                    help="Random seed for --sample (default 0, for reproducibility)")
    ap.add_argument("--refilter", action="store_true",
                    help="Re-run flow_filter even if filtered XMLs already exist "
                         "(default: reuse them)")
    ap.add_argument("--output-dir", default=None,
                    help="Directory to write results into. If omitted, a new "
                         "timestamped folder output/slice_results_YYMMDD_HHMMSS/ "
                         "is created (never overwrites previous runs).")
    args = ap.parse_args()

    # Decide result directory: explicit --output-dir, else timestamped folder.
    if args.output_dir:
        result_dir = Path(args.output_dir)
        if not result_dir.is_absolute():
            result_dir = SLICING_DIR / result_dir
    else:
        stamp = datetime.now().strftime("%y%m%d_%H%M%S")
        result_dir = OUTPUT_DIR / f"slice_results_{stamp}"

    print("== java-vuln-detection slicing runner ==")
    joern_cli = find_joern(args.joern)
    print(f"[joern] using: {joern_cli}")
    ensure_servlet_jar()
    ensure_support_jar()
    env_path = write_env(joern_cli)
    filter_xmls(args.only, args.refilter)
    run_batch(env_path, args.per_cwe, args.only, args.force,
              args.sample, args.seed, result_dir)


if __name__ == "__main__":
    main()
