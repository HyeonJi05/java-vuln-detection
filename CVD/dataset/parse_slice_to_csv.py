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
import sys
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


class FlowLabel(NamedTuple):
    target: int
    source_line: int | None
    sink_line: int | None
    source_file: str
    sink_file: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--txt", required=True, type=Path, help="Slicing result txt file (e.g. cwe369.txt).")
    parser.add_argument(
        "--xml",
        type=Path,
        default=None,
        help=(
            "source_sink_classified.xml for the same CWE. Defaults to "
            "java_sard_source_sink/source_sink_dataset/cwe{N}_source_sink_classified.xml "
            "where N is read from the txt file's '# CWE-N:' header."
        ),
    )
    parser.add_argument(
        "--juliet-root",
        type=Path,
        default=REPO_ROOT / "juliet-java-test-suite",
        help="Root of the juliet-java-test-suite checkout (default: repo's juliet-java-test-suite/).",
    )
    parser.add_argument("--output", required=True, type=Path, help="Output CSV path.")
    parser.add_argument("--project", default="Juliet-Java", help="Value for the 'project' column.")
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
            target = 1 if function_name.rsplit("::", 1)[-1] == "bad" else 0
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


def read_source_lines(java_root: Path, cwe_number: int, relative_path: str, line_numbers: list[int]) -> list[str] | None:
    source_path = java_root / f"juliet-cwe{cwe_number}" / relative_path
    if not source_path.is_file():
        return None
    file_lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    code_lines = []
    for line_no in line_numbers:
        if line_no < 1 or line_no > len(file_lines):
            return None
        code_lines.append(file_lines[line_no - 1])
    return code_lines


def main() -> None:
    args = parse_args()

    cwe_number = detect_cwe_number(args.txt)
    xml_path = args.xml or (
        REPO_ROOT / "java_sard_source_sink" / "source_sink_dataset" / f"cwe{cwe_number}_source_sink_classified.xml"
    )
    if not xml_path.is_file():
        raise FileNotFoundError(f"source_sink_classified.xml not found: {xml_path}")

    flow_labels = load_flow_labels(xml_path)
    flow_blocks = iter_flow_blocks(args.txt)

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
            code_lines = read_source_lines(args.juliet_root, cwe_number, relative_path, line_numbers)
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
                "project": args.project,
                "dataset_type": args.dataset_type,
                "processed_func": processed_func,
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
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
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
