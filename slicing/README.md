# slicing

Juliet Java 취약점 데이터셋의 source/sink 흐름을 [joern](https://joern.io)으로
슬라이싱하는 단계입니다. 추출(extraction) 단계가 만든
`java_sard_source_sink/source_sink_dataset/`의 XML을 입력으로 받아,
각 flow(source → sink)에 대한 PDG 슬라이스를 생성합니다.

파이프라인 상 위치: **추출 → 슬라이싱(여기) → 탐지**

## 출처

`cpg_builder.py`와 `flow_filter.py`는 팀원 SAN2G1의 저장소에서 가져온 것이며,
수정 없이 그대로 사용합니다. 배치 슬라이싱에 쓰는 `script/pdg_slice_batch.sc`도
원본 저장소의 슬라이싱 로직(`pdg_slice.sc`)을 그대로 담고 있습니다.

- 원본: https://github.com/SAN2G1/joern-juliet-slicer

이 폴더는 위 코드를 이 저장소에 통합하면서, 실행 환경 준비를 자동화하고
슬라이싱 실행 방식을 최적화한 버전입니다. 원본 슬라이싱 로직 자체는 바꾸지
않았습니다. 원본의 `pdg_slice.sc` / `run_pdg_slice.sh`(flow 하나씩 실행하는
방식)는 이 폴더에는 두지 않았으며, 필요하면 위 원본 저장소에서 확인할 수
있습니다.

## 사전 요구사항

두 가지만 미리 설치하면 됩니다. 나머지(라이브러리 JAR, 환경 설정)는
`run_slicing.py`가 자동으로 준비합니다.

- **JDK 17**
  ```bash
  sudo apt install openjdk-17-jdk
  ```
- **joern** (설치 후 경로는 자동 탐지되며, 필요하면 `--joern`으로 지정)
  ```bash
  mkdir -p ~/joern && cd ~/joern
  curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
  chmod u+x joern-install.sh
  ./joern-install.sh --interactive
  ```

또한 Python 의존성(저장소 루트 `requirements.txt`)과 juliet 서브모듈이
필요합니다.
```bash
pip install -r ../requirements.txt
git submodule update --init juliet-java-test-suite   # 저장소 루트에서
```

## 사용법

```bash
cd slicing
python3 run_slicing.py --per-cwe 5
```

주요 옵션:

- `--per-cwe N` : CWE마다 앞에서 N개 테스트케이스만 처리 (기본 5).
  `--per-cwe 0`으로 지정하면 모든 테스트케이스를 처리합니다.
- `--only 78 89` : 지정한 CWE 번호만 처리 (CWE 선택일 뿐이며, 각 CWE에서
  몇 개 테스트케이스를 처리할지는 `--per-cwe`가 따로 결정합니다)
- `--joern <경로>` : joern-cli 경로 직접 지정 (자동 탐지 실패 시)
- `--force` : 이미 만든 CPG도 다시 빌드
- `--refilter` : 이미 필터링된 XML이 있어도 다시 필터링

`--only`(어떤 CWE)와 `--per-cwe`(각 CWE에서 테스트케이스 몇 개)는 서로 다른
축이며 조합할 수 있습니다.

```bash
python3 run_slicing.py --only 78              # CWE-78, 앞 5개 테스트케이스(기본)
python3 run_slicing.py --only 78 --per-cwe 0  # CWE-78의 모든 테스트케이스
python3 run_slicing.py --per-cwe 0            # 모든 CWE의 모든 테스트케이스
```

결과는 `output/slice_results/cwe{번호}.txt`에 저장됩니다.

## `run_slicing.py`가 자동으로 하는 일

원본은 `setting.sh`를 각자 환경에 맞게 수정하고, servlet JAR을 직접 받고,
`.env`를 만들고, 데이터 경로를 지정하는 등의 준비가 필요했습니다.
`run_slicing.py`는 이 과정을 대신합니다.

1. **joern 위치 탐지** — 흔한 설치 경로를 확인하고, 없으면 설치 방법을 안내합니다.
2. **servlet API JAR 준비** — `deps/`에 없으면 Maven Central에서 내려받습니다.
   joern이 웹 입력(`request.getParameter` 등)이 있는 테스트케이스를 분석할 때
   필요합니다.
3. **juliet support JAR 준비** — `deps/`에 없으면 저장소 루트의
   `juliet-java-test-suite` 서브모듈에서 support 클래스를 빌드해 JAR로 묶고,
   서브모듈에 남은 빌드 산출물은 정리합니다. joern이 Juliet 공통 클래스
   (`AbstractTestCase` 등)를 분석할 때 필요합니다. 원본처럼 juliet을 별도로
   다시 clone하지 않고, 이미 있는 루트 서브모듈을 재사용합니다.
4. **`.env` 생성** — 위 경로들을 모아 임시 `.env`를 만들어 `cpg_builder.py`에
   넘깁니다. 팀원 코드는 수정하지 않고 그대로 사용합니다.
5. **필터링 → CPG 빌드 → 슬라이싱** — 추출 단계 결과인 저장소 루트의
   `java_sard_source_sink/source_sink_dataset/`을 입력으로 자동으로 사용합니다.
   데이터 경로를 따로 지정할 필요는 없습니다. 이후 아래 방식으로 실행합니다.

한 번 만든 것(JAR, 필터링 결과, CPG)은 다시 실행할 때 재사용하며,
다시 만들려면 `--refilter` 또는 `--force`를 사용합니다.

## 슬라이싱 실행 방식 최적화

원본 저장소는 flow 하나마다 `run_pdg_slice.sh`를 호출했습니다. 이 스크립트는
매번 joern을 새로 실행하고, 그 안에서 CPG를 `importCpg`로 다시 불러옵니다. 즉
같은 테스트케이스에 flow가 여러 개여도 그때마다 joern JVM이 새로 뜨고 같은
CPG가 반복해서 로드됐습니다.

이 실행 방식에는 세 단계의 의존 관계가 있습니다.

- **joern 실행**: 어떤 CPG·flow와도 무관 → 한 번만 띄우면 됨
- **CPG 로드**: 테스트케이스 단위 → 같은 테스트케이스의 여러 flow가 공유
- **슬라이싱**: flow 단위

원본은 가장 안쪽(flow)에서 매번 joern 실행과 CPG 로드를 반복했기 때문에,
슬라이싱 연산 자체는 빠른데도 준비 비용이 크게 누적됐습니다.

이 폴더의 배치 방식은 이 구조를 다음과 같이 바꿉니다. 아래 세 파일은 모두
이 통합 과정에서 새로 작성한 것이며, 슬라이스를 실제로 계산하는 핵심 로직만
원본 `pdg_slice.sc`에서 그대로 가져와 재사용합니다.

- `script/pdg_slice_batch.sc` : 여러 (CPG, source/sink) 작업을 담은 목록 파일을
  받아, **CPG 단위로 묶어 한 CPG당 `importCpg`를 한 번만** 수행하고, 그 안에서
  각 flow를 슬라이싱합니다. 목록을 읽어 CPG별로 묶고 반복하는 바깥 구조는 새로
  작성했고, 각 flow를 슬라이스하는 안쪽 로직은 원본 `pdg_slice.sc`의 것을 그대로
  씁니다. 한 flow가 실패해도 나머지는 계속 처리합니다.
- `script/run_pdg_slice_batch.sh` : 목록 파일 하나를 받아 **joern을 한 번만**
  호출합니다. 즉 목록 파일 하나가 joern 실행 한 번에 대응합니다. (원본
  `run_pdg_slice.sh`는 flow 하나의 인자를 받았고, 이쪽은 목록 파일을 받는 새
  wrapper입니다.)
- `run_slicing.py` : CWE마다 그 CWE의 모든 flow를 **목록 파일 하나로 모아서**
  위 `run_pdg_slice_batch.sh`에 넘깁니다. 목록 파일 하나 = joern 한 번이므로,
  CWE 하나가 joern 실행 한 번이 됩니다.

결과적으로 joern 실행 횟수는 CWE 단위로, CPG 로드는 테스트케이스 단위로
줄어듭니다. 앞의 의존 관계에 맞게, 한 번만 하면 되는 일을 한 번만 하도록
바꾼 것입니다.

슬라이싱 로직을 바꾼 것이 아니라 실행 순서만 바꾼 것이므로, 슬라이스 결과는
원본 방식과 동일합니다(트레이스 나열 순서는 joern 특성상 실행마다 달라질 수
있으나, 트레이스 집합 자체는 같습니다).

## 폴더 구성

```
slicing/
├── run_slicing.py              # 진입점 (환경 자동 준비 + 배치 실행)
├── cpg_builder.py              # (SAN2G1) CPG 빌드
├── flow_filter.py              # (SAN2G1) source/sink XML 필터링
├── script/
│   ├── pdg_slice_batch.sc      # CPG 단위로 묶어 처리하는 배치 버전
│   │                           #   (SAN2G1의 pdg_slice.sc 로직을 그대로 사용)
│   └── run_pdg_slice_batch.sh  # 목록 파일 하나로 joern을 한 번 실행
└── output/
    └── slice_results/          # 슬라이싱 결과 (커밋)
        ├── cwe{번호}.txt        # 배치 방식 결과
        └── test/               # 원본 방식으로 뽑은 결과 (비교용)
```

`deps/`, `.env`, `output/CPG/`, `output/jobs/` 등 재생성되는 파일과 환경 파일은
저장소에 포함하지 않습니다(`.gitignore`).
