# Extraction — source/sink dataset

Stage 1 of the java-vuln-detection pipeline: extract and verify source/sink
pairs from the Java SARD (Juliet) test suite.

This repository builds a **trace-unit (source → sink) dataset** from the
Java SARD (Juliet) test suite, as the front-end stage of an AI-based
vulnerability detection pipeline. Extraction and verification of source/sink
pairs are complete; downstream stages (joern-based trace slicing, LLM/RAG
detection) will be added later.

## Current stage

Complete. Two scripts are provided:

- `tools/run_pipeline_all_cwes.py` — runs the source/sink extraction pipeline
  over all CWEs in the Juliet Java test suite, collects per-CWE result XMLs,
  and writes run logs.
- `tools/verify_source_sink.py` — verifies that extracted source/sink line
  numbers match the original `.java` sources, and writes verification logs.

## Requirements

- **Python 3.9–3.11** (tree_sitter_languages 1.10.2 does not support 3.12+)
- Dependencies in `requirements.txt`

```bash
# Create a virtual environment with Python 3.11
# Windows:
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
# Linux/Mac:
python3.11 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

The dataset is a git submodule. After cloning:

```bash
git submodule update --init
```

## Usage

### 1. Extract source/sink pairs (all CWEs)

```bash
python extraction/tools/run_pipeline_all_cwes.py
```

Options:

- `--only 78 190` — run only specific CWEs
- `--skip 113` — skip specific CWEs
- `--output-dir <path>` — where classified XMLs are collected
  (default: `java_sard_source_sink/source_sink_dataset/`)
- `--log-dir <path>` — where run logs are written
  (default: `java_sard_source_sink/logs/`)

Per-CWE outputs are written under `artifacts/pipeline-runs/java-cwe{N}-source-sink/`,
and the final classified XML for each CWE is collected into the output folder
`java_sard_source_sink/source_sink_dataset/` as
`cwe{N}_source_sink_classified.xml`.

### 2. Verify extracted line numbers

```bash
python extraction/tools/verify_source_sink.py
```

Options:

- `--cwe 78 113` — verify only specific CWEs
- `--xml <path> --source-root <path>` — verify a single XML against a source root

Verification logs are written to `java_sard_source_sink/logs/`
(`verify_summary.txt`, `verify_report.csv`, `verify_mismatches.txt`,
`verify_known_warnings.txt`).

## How extraction works

Each CWE is processed through four stages:

1. **manifest** (`generate_juliet_manifest.py`) — build an XML list (manifest)
   of the test-case files to analyze
2. **comment scan** (`scan_manifest_comments.py`) — find `POTENTIAL FLAW` / `FIX`
   comments and the code they refer to
3. **flow tagging** (`add_flow_tags_to_testcase.py`) — group candidates into
   flows (b2b / b2g / g2b)
4. **classification** (`classify_flow_comments_by_function_name.py`) — assign
   each item a role (source / sink) and safety label (bad / good)

The result is one `source_sink_classified.xml` per CWE, where each `<flow>`
lists its source and sink with line, code, role, and safety.

The line numbers and vulnerable function/variable keywords in this result are
used as anchors for joern-based code slicing in the next stage.

## Notes

- CWEs whose vulnerability is not a source→sink data flow (resource management,
  concurrency, design issues, unsafe-API use, etc.) produce **empty** output.
  This is expected — they are outside the scope of a source/sink dataset.
- A small number of items are recorded as `WARNING_NOT_FOUND`: another comment
  (e.g. a NOTE) containing an extraction keyword such as `flaw` is scanned by
  mistake, and no real code is found beneath it. This is a known extractor
  limitation. Such items are tallied separately during verification and are
  not counted as errors.
- In some cases the item extracted below a comment is another comment
  (`/* ... */`), an opening brace (`{`), a variable declaration, etc. The line
  number is still correct, but extracting the vulnerable function/variable
  keyword from such items may be difficult.

## Layout (under `extraction/`)

```
extraction/
  tools/
    run_pipeline_all_cwes.py     # batch runner (all CWEs)
    verify_source_sink.py        # line-number verification
    generate_juliet_manifest.py  # stage 1
    stage/                       # stage modules
    shared/                      # shared helpers
  experiments/
    epic001_manifest_comment_scan/    # stage 2 script
    epic001c_testcase_flow_partition/ # stage 3 script
    epic002/                          # stage 4 script
```

The dataset (`juliet-java-test-suite/`) and output
(`java_sard_source_sink/`) live at the project root, not under `extraction/`.

