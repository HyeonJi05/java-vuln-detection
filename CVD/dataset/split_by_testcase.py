#!/usr/bin/env python3
"""Split a CVD-format CSV into RAG-corpus / evaluation CSVs by testcase
(everything before `_flow{N}` in unique_id, e.g. `cwe369_tc929`), so flows
from one testcase -- which tend to share near-identical code -- never land
on both sides of the split.
"""

from __future__ import annotations

import argparse
import csv
import random
import re
from pathlib import Path


TESTCASE_RE = re.compile(r"^(.+)_flow\d+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Input CSV to split.")
    parser.add_argument("--train-output", required=True, type=Path, help="Output CSV for the corpus split (dataset_type=train_val).")
    parser.add_argument("--test-output", required=True, type=Path, help="Output CSV for the evaluation split (dataset_type=test).")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Fraction of testcases assigned to the corpus split.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for shuffling testcases.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    with args.input.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    rows_by_testcase: dict[str, list[dict[str, str]]] = {}
    dropped = 0
    for row in rows:
        match = TESTCASE_RE.search(row.get("unique_id", ""))
        if not match:
            dropped += 1
            continue
        rows_by_testcase.setdefault(match.group(1), []).append(row)

    testcases = list(rows_by_testcase)
    random.Random(args.seed).shuffle(testcases)
    cut = round(len(testcases) * args.train_ratio)
    train_testcases = set(testcases[:cut])
    test_testcases = set(testcases[cut:])

    train_rows = []
    test_rows = []
    for testcase, testcase_rows in rows_by_testcase.items():
        target_type = "train_val" if testcase in train_testcases else "test"
        for row in testcase_rows:
            row = dict(row)
            row["dataset_type"] = target_type
            (train_rows if testcase in train_testcases else test_rows).append(row)

    for path, out_rows in ((args.train_output, train_rows), (args.test_output, test_rows)):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            writer.writerows(out_rows)

    print(f"Input: {args.input} ({len(rows)} rows, {dropped} dropped for unmatched unique_id)")
    print(f"Testcases: {len(testcases)} total -> {len(train_testcases)} train_val / {len(test_testcases)} test")
    print(f"Rows written: {len(train_rows)} -> {args.train_output}")
    print(f"Rows written: {len(test_rows)} -> {args.test_output}")


if __name__ == "__main__":
    main()
