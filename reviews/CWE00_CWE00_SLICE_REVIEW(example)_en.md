# Manual Review Notes for Slicing Results

## Review Information

- Reviewer:
- Review date:
- Assigned CWEs: CWE-00, CWE-00

## Review Target Summary

Select five testcases from each of two CWEs.

| No. | CWE | Testcase index | Primary Java filename | Flow type |
|---:|---:|---:|---|---|
| 1 |  |  |  |  |
| 2 |  |  |  |  |
| 3 |  |  |  |  |
| 4 |  |  |  |  |
| 5 |  |  |  |  |
| 6 |  |  |  |  |
| 7 |  |  |  |  |
| 8 |  |  |  |  |
| 9 |  |  |  |  |
| 10 |  |  |  |  |

## Testcase Reviews

### [1] CWE-00 / Testcase 00

- Java filenames:
    - Filename 1
    - Filename 2 (if the testcase contains two or more files)
- Slicing result file:

#### (1) Flow 00 [Type (`b2b`, `b2g`, `g2b`, etc.)]

- Source: `filename#line`
- Sink: `filename#line`

**Expected Trace**

```text
[filename] | line=00 | [code]
[filename] | line=00 | [code]
...
```

**Actual Trace**

```text
[filename] | line=00 | [code]
[filename] | line=00 | [code]
...
```

**Comparison Result**

- Slice scope: [ Appropriate / Excessive / Insufficient ]
- Rationale: Describe how the actual trace differs from the expected trace.
