# java-vuln-detection

소프트웨어 코드 취약점 탐지 프로젝트 — Java 트랙.

이 저장소는 Java SARD(Juliet) 테스트 수트로부터 **trace 단위(source → sink)
데이터셋**을 구축합니다. AI 기반 취약점 탐지 파이프라인의 앞단에 해당하며,
현재 source/sink 쌍을 추출하고 검증하는 단계까지 완료되었습니다. 이후 단계
(joern 기반 trace 슬라이싱, LLM/RAG 탐지)는 추후 추가될 예정입니다.

## 현재 단계

여기까지 완료되었습니다. 다음 두 스크립트를 제공합니다:

- `tools/run_pipeline_all_cwes.py` — Juliet Java 테스트 수트 전체 CWE에 대해
  source/sink 추출 파이프라인을 실행하고, CWE별 결과 XML을 모으며 실행 로그를 남깁니다.
- `tools/verify_source_sink.py` — 추출된 source/sink의 줄 번호가 원본 `.java`와
  일치하는지 검증하고, 검증 로그를 남깁니다.

## 요구 사항

- **Python 3.9–3.11** (tree_sitter_languages 1.10.2가 3.12+를 지원하지 않음)
- 의존성은 `requirements.txt` 참고

```bash
# Python 3.11 로 가상환경 생성
# Windows:
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
# Linux/Mac:
python3.11 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

데이터셋은 git 서브모듈입니다. clone 후 다음을 실행하세요:

```bash
git submodule update --init
```

## 사용법

### 1. source/sink 쌍 추출 (전체 CWE)

```bash
python tools/run_pipeline_all_cwes.py
```

옵션:

- `--only 78 190` — 특정 CWE만 실행
- `--skip 113` — 특정 CWE 제외
- `--output-dir <경로>` — 분류된 XML을 모을 위치
  (기본값: `java_sard_source_sink/source_sink_dataset/`)
- `--log-dir <경로>` — 실행 로그 위치
  (기본값: `java_sard_source_sink/logs/`)

CWE별 산출물은 `artifacts/pipeline-runs/java-cwe{N}-source-sink/` 아래에
생성되고, 각 CWE의 최종 분류 XML은 출력 폴더
`java_sard_source_sink/source_sink_dataset/`에
`cwe{N}_source_sink_classified.xml` 형태로 모입니다.

### 2. 추출된 줄 번호 검증

```bash
python tools/verify_source_sink.py
```

옵션:

- `--cwe 78 113` — 특정 CWE만 검증
- `--xml <경로> --source-root <경로>` — 단일 XML을 지정한 원본과 대조

검증 로그는 `java_sard_source_sink/logs/`에 기록됩니다
(`verify_summary.txt`, `verify_report.csv`, `verify_mismatches.txt`,
`verify_known_warnings.txt`).

## 추출 방식

각 CWE는 네 단계를 거칩니다:

1. **manifest** (`generate_juliet_manifest.py`) — 분석할 테스트케이스 파일들의
   목록(manifest)을 XML로 생성
2. **주석 스캔** (`scan_manifest_comments.py`) — `POTENTIAL FLAW` / `FIX`
   주석과 그 주석이 가리키는 코드를 찾음
3. **flow 태깅** (`add_flow_tags_to_testcase.py`) — 후보들을 flow 단위로
   묶음 (b2b / b2g / g2b)
4. **분류** (`classify_flow_comments_by_function_name.py`) — 각 항목에
   역할(source / sink)과 안전성 라벨(bad / good)을 부여

결과는 CWE별 `source_sink_classified.xml` 하나이며, 각 `<flow>`가 자신의
source와 sink를 line, code, role, safety와 함께 나열합니다.

이 결과의 줄 번호와 취약 함수/변수 키워드는 다음 단계에서 joern 기반 코드
슬라이싱의 기준점으로 사용됩니다.

## 참고 사항

- 취약점이 source→sink 데이터 흐름이 아닌 CWE(자원 관리, 동시성, 설계 결함,
  위험 API 사용 등)는 **빈(empty)** 결과가 나옵니다. 이는 정상이며, source/sink
  데이터셋의 대상 범위 밖입니다.
- 일부 항목은 `WARNING_NOT_FOUND`로 기록됩니다. `flaw` 같은 추출 키워드가
  포함된 다른 주석(NOTE 등)이 잘못 스캔되어 그 아래에서 실제 코드를 찾지 못한
  경우로, 알려진 추출기 한계입니다. 검증 시 별도로 집계되며 오류로 세지 않습니다.
- 주석 아래에서 또 다른 주석(`/* ... */`), 여는 중괄호(`{`), 변수 선언 등이
  추출되는 경우가 있습니다. 이때 줄 번호(line) 기준으로는 문제가 없을 수
  있으나, 취약 함수/변수 키워드 추출은 어려울 수 있습니다.

## 저장소 구조

```
tools/
  run_pipeline_all_cwes.py       # 배치 실행기 (전체 CWE)
  verify_source_sink.py          # 줄 번호 검증
  generate_juliet_manifest.py    # 1단계
  stage/                         # 단계 모듈
  shared/                        # 공용 헬퍼
experiments/
  epic001_manifest_comment_scan/ # 2단계 스크립트
  epic001c_testcase_flow_partition/ # 3단계 스크립트
  epic002/                       # 4단계 스크립트
juliet-java-test-suite/          # 데이터셋 (git 서브모듈)
```

## 로드맵

- [x] Juliet Java에서 source/sink 추출
- [x] 줄 번호 검증
- [ ] joern 기반 trace 슬라이싱
- [ ] LLM + RAG 취약점 탐지

## 라이선스

이 프로젝트는 상위 파이프라인의 코드를 재사용하며 **GNU AGPL v3**로
배포됩니다 (`LICENSE` 참고).
