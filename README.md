# java-vuln-detection

Software code vulnerability detection project — Java track.

The goal is an AI-based vulnerability detector trained on **trace-unit
(source → sink) data** rather than function-level labels. The pipeline turns
the Java SARD (Juliet) test suite into labeled source/sink traces, slices the
relevant code with joern, and (later) detects vulnerabilities with an
LLM/RAG model.

> 한국어 README: [README.ko.md](README.ko.md)

## Pipeline

```
extraction  ->  slicing  ->  detection
```

| Stage | Folder | What it does | Status |
| --- | --- | --- | --- |
| **Extraction** | [`extraction/`](extraction/) | Extract and verify source/sink pairs from the Juliet Java test suite (per CWE) | Done |
| **Slicing** | [`joern-juliet-slicer`](joern-juliet-slicer/) | Build joern CPGs and slice code around each source/sink using its line numbers and keywords | In progress |
| **Detection** | `detection/` | LLM + RAG vulnerability detection | Planned |

Each stage has its own README with detailed setup and usage.

## Data flow

- **Extraction** writes per-CWE classified XMLs to
  `java_sard_source_sink/source_sink_dataset/` (`cwe{N}_source_sink_classified.xml`).
- **Slicing** reads those XMLs as its input.

The dataset itself lives in `juliet-java-test-suite/` (a git submodule).
After cloning:

```bash
git submodule update --init
```

## Repository layout

```
extraction/               # stage 1: source/sink extraction + verification
joern-juliet-slicer/      # stage 2: joern slicing (submodule)
detection/                # stage 3: LLM + RAG detection (planned)
juliet-java-test-suite/   # dataset (git submodule)
java_sard_source_sink/    # extraction output (consumed by slicing)
```

## Roadmap

- [x] Source/sink extraction from Juliet Java
- [x] Line-number verification
- [ ] joern-based trace slicing
- [ ] LLM + RAG vulnerability detection

## License

Distributed under the **GNU AGPL v3** (see `LICENSE`).
