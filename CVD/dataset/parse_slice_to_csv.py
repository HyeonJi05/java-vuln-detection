#!/usr/bin/env python3
"""Join a joern slice txt, its source_sink_classified.xml labels, and the
Juliet source tree into a CVD CSV. processed_func never includes file names:
Juliet file names encode the CWE type (e.g. "CWE113_HTTP_Response_Splitting__..."),
which would leak the label into the code text handed to the LLM.
"""

from __future__ import annotations

import argparse
import csv
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import NamedTuple


REPO_ROOT = Path(__file__).resolve().parents[2]

CSV_FIELDNAMES = [
    "file_name",
    "unique_id",
    "target",
    "source_line",
    "sink_line",
    "project",
    "dataset_type",
    "processed_func",
]

FLOW_HEADER_RE = re.compile(r"^##########\s*FLOW\s+tc(\d+)_flow(\d+)\s*##########\s*$")
CWE_HEADER_RE = re.compile(r"^#\s*CWE-(\d+)\s*:")
BACKWARD_SLICE_START = "=== DDG + CDG Backward Slice ==="
BACKWARD_SLICE_END_PREFIXES = ("=== PDG Slice Summary ===", "=== Summary ===")
SLICE_LINE_RE = re.compile(r"^(?P<path>.*?)\s*\|\s*line=(?P<line>\d+),\s*col=(?P<col>\d+)\s*\|\s*(?P<code>.*)$")


def function_indicates_bad(function_name: str) -> bool:
    """True if a flow's function marks it vulnerable ("bad").

    Java names are scoped ("Class::bad"); C names are flat
    ("CWE15_..._w32_01_bad"), so only the "::" case can be checked with
    equality -- the flat case needs a suffix check instead.
    """
    tail = function_name.rsplit("::", 1)[-1]
    return tail == "bad" or tail.endswith("_bad")


class FlowLabel(NamedTuple):
    target: int
    source_line: int | None
    sink_line: int | None
    source_file: str
    sink_file: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--language", choices=("java", "c"), default="java",
                    help="Source language (default: java).")
    parser.add_argument("--txt", required=True, type=Path,
                    help="Slicing result txt file (e.g. cwe369.txt), or a directory "
                         "containing cwe*.txt files (batch mode: one CSV per file, "
                         "named cwe{N}.csv, written under --output).")
    parser.add_argument(
        "--xml",
        type=Path,
        default=None,
        help=(
            "source_sink_classified.xml for the same CWE. Defaults to "
            "{java_sard_source_sink,c_sard_source_sink}/source_sink_dataset/"
            "cwe{N}_source_sink_classified.xml (per --language) where N is read "
            "from the txt file's '# CWE-N:' header."
        ),
    )
    parser.add_argument(
        "--juliet-root",
        type=Path,
        default=None,
        help="Root of the Juliet checkout. Default: juliet-java-test-suite/ (java) "
             "or juliet-test-suite-c/ (c).",
    )
    parser.add_argument("--output", required=True, type=Path,
                    help="Output CSV path (single-file mode), or output directory "
                         "(batch mode, i.e. when --txt is a directory).")
    parser.add_argument("--combined-output", type=Path, default=None,
                    help="Batch mode only: also write every row from every "
                         "cwe*.txt into a single merged CSV at this path.")
    parser.add_argument("--project", default=None,
                    help="Value for the 'project' column. Default: Juliet-Java or Juliet-C (per --language).")
    parser.add_argument("--dataset-type", default="test", help="Value for the 'dataset_type' column.")
    return parser.parse_args()


def detect_cwe_number(txt_path: Path) -> int:
    with txt_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = CWE_HEADER_RE.match(line.strip())
            if match:
                return int(match.group(1))
    raise ValueError(f"Could not find a '# CWE-N:' header in {txt_path}")


def load_flow_labels(xml_path: Path) -> dict[tuple[int, int], FlowLabel]:
    tree = ET.parse(xml_path)
    labels: dict[tuple[int, int], FlowLabel] = {}
    for testcase in tree.getroot().findall("testcase"):
        testcase_index = int(testcase.get("testcase_index"))
        for flow in testcase.findall("flow"):
            flow_index = int(flow.get("flow_index"))
            source_line = None
            sink_line = None
            source_file = ""
            sink_file = ""
            function_name = ""
            for node in list(flow):
                role = node.get("role")
                line = node.get("line")
                if role == "source" and line is not None:
                    source_line = int(line)
                    source_file = node.get("file", "")
                elif role == "sink" and line is not None:
                    sink_line = int(line)
                    sink_file = node.get("file", "")
                function_name = function_name or node.get("function", "")
            target = 1 if function_indicates_bad(function_name) else 0
            labels[(testcase_index, flow_index)] = FlowLabel(
                target=target,
                source_line=source_line,
                sink_line=sink_line,
                source_file=source_file,
                sink_file=sink_file,
            )
    return labels


def iter_flow_blocks(txt_path: Path) -> list[tuple[int, int, str]]:
    """Return (testcase_index, flow_index, block_text) for each FLOW section."""
    text = txt_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    headers = []
    for line_no, line in enumerate(lines):
        match = FLOW_HEADER_RE.match(line.strip())
        if match:
            headers.append((line_no, int(match.group(1)), int(match.group(2))))

    blocks = []
    for index, (start_line, testcase_index, flow_index) in enumerate(headers):
        end_line = headers[index + 1][0] if index + 1 < len(headers) else len(lines)
        block_text = "\n".join(lines[start_line:end_line])
        blocks.append((testcase_index, flow_index, block_text))
    return blocks


def extract_backward_slice_lines(block_text: str) -> list[tuple[str, int]]:
    """Return [(relative_path, line_number), ...] from the block's backward slice section."""
    start = block_text.find(BACKWARD_SLICE_START)
    if start == -1:
        return []
    remainder = block_text[start + len(BACKWARD_SLICE_START):]

    end = len(remainder)
    for prefix in BACKWARD_SLICE_END_PREFIXES:
        pos = remainder.find(prefix)
        if pos != -1:
            end = min(end, pos)
    section = remainder[:end]

    results = []
    for raw_line in section.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = SLICE_LINE_RE.match(line)
        if not match:
            continue
        results.append((match.group("path"), int(match.group("line"))))
    return results


def group_slice_lines_by_file(slice_lines: list[tuple[str, int]]) -> list[tuple[str, list[int]]]:
    """Group by relative path (first-seen order), each with its sorted, deduped line numbers."""
    lines_by_path: dict[str, set[int]] = {}
    order: list[str] = []
    for path, line_no in slice_lines:
        if path not in lines_by_path:
            lines_by_path[path] = set()
            order.append(path)
        lines_by_path[path].add(line_no)
    return [(path, sorted(lines_by_path[path])) for path in order]


def resolve_c_cwe_dir(juliet_root: Path, cwe_number: int) -> Path | None:
    """C/C++ Juliet layout: <root>/testcases/CWE{N}_{Name}/."""
    matches = sorted((juliet_root / "testcases").glob(f"CWE{cwe_number}_*"))
    return matches[0] if matches else None


def read_source_lines(
    juliet_root: Path, cwe_number: int, relative_path: str, line_numbers: list[int], language: str
) -> list[str] | None:
    if language == "java":
        source_path = juliet_root / f"juliet-cwe{cwe_number}" / relative_path
    else:
        cwe_dir = resolve_c_cwe_dir(juliet_root, cwe_number)
        if cwe_dir is None:
            return None
        source_path = cwe_dir / relative_path
        if not source_path.is_file():
            source_path = juliet_root / "testcasesupport" / relative_path
    if not source_path.is_file():
        return None
    file_lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    code_lines = []
    for line_no in line_numbers:
        if line_no < 1 or line_no > len(file_lines):
            return None
        code_lines.append(file_lines[line_no - 1])
    return code_lines


def convert_file(
    txt_path: Path, output_path: Path, args: argparse.Namespace
) -> tuple[dict[str, int], list[dict[str, str]]]:
    """Convert one slicing-result txt file into one CSV. Returns (row/skip counts, rows)."""
    cwe_number = detect_cwe_number(txt_path)
    sard_dir = "java_sard_source_sink" if args.language == "java" else "c_sard_source_sink"
    xml_path = args.xml or (
        REPO_ROOT / sard_dir / "source_sink_dataset" / f"cwe{cwe_number}_source_sink_classified.xml"
    )
    if not xml_path.is_file():
        raise FileNotFoundError(f"source_sink_classified.xml not found: {xml_path}")

    juliet_root = args.juliet_root or (
        REPO_ROOT / ("juliet-java-test-suite" if args.language == "java" else "juliet-test-suite-c")
    )
    project = args.project or ("Juliet-Java" if args.language == "java" else "Juliet-C")

    flow_labels = load_flow_labels(xml_path)
    flow_blocks = iter_flow_blocks(txt_path)

    rows = []
    skipped_no_label = 0
    skipped_no_trace = 0
    skipped_no_source = 0

    for testcase_index, flow_index, block_text in flow_blocks:
        label = flow_labels.get((testcase_index, flow_index))
        if label is None:
            skipped_no_label += 1
            continue

        slice_lines = extract_backward_slice_lines(block_text)
        files = group_slice_lines_by_file(slice_lines)
        if not files:
            skipped_no_trace += 1
            continue

        file_blocks = []
        for relative_path, line_numbers in files:
            code_lines = read_source_lines(juliet_root, cwe_number, relative_path, line_numbers, args.language)
            if code_lines is None:
                file_blocks = None
                break
            file_blocks.append((Path(relative_path).name, code_lines))
        if file_blocks is None:
            skipped_no_source += 1
            continue

        file_name = "\n".join(name for name, _ in file_blocks)
        processed_func = "\n\n".join("\n".join(code_lines) for _, code_lines in file_blocks)
        source_line = f"{label.source_file}:{label.source_line}" if label.source_line is not None else ""
        sink_line = f"{label.sink_file}:{label.sink_line}" if label.sink_line is not None else ""
        rows.append(
            {
                "file_name": file_name,
                "unique_id": f"cwe{cwe_number}_tc{testcase_index}_flow{flow_index}",
                "target": str(label.target),
                "source_line": source_line,
                "sink_line": sink_line,
                "project": project,
                "dataset_type": args.dataset_type,
                "processed_func": processed_func,
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)

    total_flows = len(flow_blocks)
    print(f"CWE: {cwe_number}")
    print(f"Flows in txt: {total_flows}")
    print(f"Written rows: {len(rows)}")
    print(f"Skipped (no XML label match): {skipped_no_label}")
    print(f"Skipped (no backward slice / trace): {skipped_no_trace}")
    print(f"Skipped (source file unreadable): {skipped_no_source}")
    print(f"Output: {output_path}")

    stats = {
        "flows": total_flows,
        "written": len(rows),
        "skipped_no_label": skipped_no_label,
        "skipped_no_trace": skipped_no_trace,
        "skipped_no_source": skipped_no_source,
    }
    return stats, rows


def main() -> None:
    args = parse_args()

    if not args.txt.exists():
        raise FileNotFoundError(f"--txt path does not exist: {args.txt}")

    if args.txt.is_dir():
        txt_files = sorted(args.txt.glob("cwe*.txt"))
        if not txt_files:
            raise FileNotFoundError(f"No cwe*.txt files found in {args.txt}")
        totals = {"flows": 0, "written": 0, "skipped_no_label": 0, "skipped_no_trace": 0, "skipped_no_source": 0}
        all_rows: list[dict[str, str]] = []
        for txt_path in txt_files:
            print(f"=== {txt_path.name} ===")
            output_path = args.output / f"{txt_path.stem}.csv"
            stats, rows = convert_file(txt_path, output_path, args)
            for key in totals:
                totals[key] += stats[key]
            all_rows.extend(rows)
            print()
        print("=== batch summary ===")
        print(f"Files processed: {len(txt_files)}")
        for key, value in totals.items():
            print(f"{key}: {value}")

        if args.combined_output:
            args.combined_output.parent.mkdir(parents=True, exist_ok=True)
            with args.combined_output.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=CSV_FIELDNAMES, quoting=csv.QUOTE_MINIMAL)
                writer.writeheader()
                writer.writerows(all_rows)
            print(f"Combined output ({len(all_rows)} rows): {args.combined_output}")
    else:
        convert_file(args.txt, args.output, args)


if __name__ == "__main__":
    main()
