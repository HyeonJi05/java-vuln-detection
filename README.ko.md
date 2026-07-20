# java-vuln-detection

소프트웨어 코드 취약점 탐지 프로젝트 — Java 트랙.

함수 단위 라벨이 아니라 **trace 단위(source → sink) 데이터**로 학습하는
AI 기반 취약점 탐지기를 목표로 합니다. 파이프라인은 Java SARD(Juliet)
테스트 수트를 라벨링된 source/sink trace로 변환하고, joern으로 관련 코드를
슬라이싱한 뒤, (추후) LLM/RAG 모델로 취약점을 탐지합니다.

> English README: [README.md](README.md)

## 파이프라인

```
extraction  ->  slicing  ->  detection
```

| 단계 | 폴더 | 하는 일 | 상태 |
| --- | --- | --- | --- |
| **추출(Extraction)** | [`extraction/`](extraction/) | Juliet Java 테스트 수트에서 CWE별로 source/sink 쌍을 추출·검증 | 완료 |
| **슬라이싱(Slicing)** | [`joern-juliet-slicer`](joern-juliet-slicer/) | joern CPG를 만들고, source/sink의 줄 번호·키워드를 기준으로 코드를 슬라이싱 | 진행 중 |
| **탐지(Detection)** | `detection/` | LLM + RAG 취약점 탐지 | 예정 |

각 단계는 자체 README에 상세 설정·사용법이 있습니다.

## 데이터 흐름

- **추출**은 CWE별 분류 XML을
  `java_sard_source_sink/source_sink_dataset/`에
  (`cwe{N}_source_sink_classified.xml`) 기록합니다.
- **슬라이싱**은 이 XML들을 입력으로 받습니다.

데이터셋 자체는 `juliet-java-test-suite/`(git 서브모듈)에 있습니다.
clone 후:

```bash
git submodule update --init
```

## 저장소 구조

```
extraction/               # 1단계: source/sink 추출 + 검증
joern-juliet-slicer/      # 2단계: joern 슬라이싱 (서브모듈)
detection/                # 3단계: LLM + RAG 탐지 (예정)
juliet-java-test-suite/   # 데이터셋 (git 서브모듈)
java_sard_source_sink/    # 추출 산출물 (슬라이싱이 입력으로 사용)
```

## 로드맵

- [x] Juliet Java에서 source/sink 추출
- [x] 줄 번호 검증
- [ ] joern 기반 trace 슬라이싱
- [ ] LLM + RAG 취약점 탐지

## 라이선스

**GNU AGPL v3**로 배포됩니다 (`LICENSE` 참고).
