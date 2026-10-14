# 욕설·위협 감지 서버 (threat_server)

글라스 착용자에게 들어온 말(전사문)에 욕설이나 위협이 있으면 관제 서버에 알립니다.

```
폰 앱 ──WAV + userId + variant──▶ 음성 서버 /api/transcribe (Whisper)
                                      │ 전사문
                                      ▼
                              ThreatDetector.check()   정상 / 욕설 / 위협 분류
                                      │ 욕설·위협 (확신도 ≥ 임계값)
                                      ▼
                              관제 서버 POST /api/alerts
```

## 사용자 구분과 버전

- **사용자**: 앱을 처음 실행할 때 등록한 전화번호(`userId`)
- **버전**: 앱 빌드 플레이버로 나눕니다
  - `beta` 빌드 → `variant=test`
  - `prod` 빌드 → `variant=prod`
  - 플레이버 이름은 `test`로 시작할 수 없어서 `beta`로 지었습니다

| 알람 필드 | 일반(prod) | 테스트(test) |
|---|---|---|
| `userId` 전화번호 | ✅ | ✅ |
| `transcript` 전사문 | ✅ | ✅ |
| `detectedAt` 감지 시각 | ✅ | ✅ |
| `variant` | ✅ | ✅ |
| `category` 욕설/위협 | ❌ | ✅ |
| `confidence` 모델 확신도 | ❌ | ✅ |

## 실행

```bash
pip install -r requirements.txt

# 관제 서버 (임시 수신용, 받은 알람은 GET /api/alerts로 확인)
uvicorn threat_server.control_server:app --host 0.0.0.0 --port 9000

# 감지 서버
export THREAT_MODEL_DIR=models/threat-kcelectra   # 비우면 개발용 단어 사전으로 동작
export CONTROL_SERVER_URL=http://127.0.0.1:9000/api/alerts
uvicorn threat_server.app:create_app --factory --host 0.0.0.0 --port 8002
```

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `THREAT_MODEL_DIR` | (없음) | 학습한 모델 폴더. 없으면 규칙 사전만 쓴다 (현재 기본) |
| `THREAT_HYBRID` | `1` | 모델과 규칙 사전을 함께 쓴다. `0`이면 모델만 |
| `CONTROL_SERVER_URL` | `http://127.0.0.1:9000/api/alerts` | 관제 서버 알람 주소 |
| `THREAT_THRESHOLD` | `0.7` | 이 확신도 이상일 때만 알람 (운영 권장 `0.8`, 아래 표 참고) |
| `ALERT_TIMEOUT` | `3.0` | 관제 서버 요청 타임아웃(초) |
| `CONTROL_ALERT_ENABLED` | `0` | `1`이면 위협 판정 시 관제 서버로 알람을 보낸다. 관제 연동 전이라 기본은 꺼 둔다 |

윈도우에서는 스크립트 하나로 띄울 수 있다.

```powershell
.\scripts\start.ps1              # 규칙 사전만 (기본값), 임계값 0.8
.\scripts\start.ps1 -WithModel   # 모델 + 규칙 사전 병행
.\scripts\start.ps1 -WithAlert   # 관제 서버 알람 켜기 (기본은 꺼짐)
```

### 확인

```bash
curl -X POST localhost:8002/api/threat/check -H 'content-type: application/json' \
  -d '{"userId":"010-1234-5678","text":"너 죽여버린다","variant":"test"}'
# {"type":"threat","text":"너 죽여버린다","userId":"010-1234-5678","category":"위협","confidence":1.0,"elapsed":0.001}
```

## STT 서버와 주고받는 형식

STT 서버(`whisper_server`)는 Whisper 전사가 끝나면 전사문을 이 서버로 보내고, 응답을 보고 LLM 호출 여부를 정합니다.

```
폰 ──WAV + userId + variant──▶ STT 서버 /api/transcribe
                                 │ 전사문
                                 ▼
                   POST /api/threat/check  {"userId","text","variant"}
                                 │ NDJSON 한 줄
                 ┌───────────────┴───────────────┐
           {"type":"safe"}                 {"type":"threat"}
           LLM 호출 → 답변                  LLM 건너뜀
                                           (관제 알람: CONTROL_ALERT_ENABLED=1일 때만)
```

### 요청

```json
{"userId": "010-1234-5678", "text": "<전사문>", "variant": "test"}
```

### 응답 — NDJSON (`application/x-ndjson`, 한 줄)

STT 서버의 `/ws/live` 메시지와 같은 `{"type": ..., "text": ...}` 구조입니다.

| `type` | 의미 | 필드 |
|---|---|---|
| `safe` | 이상 없음 | `text`, `elapsed` |
| `threat` | 욕설 또는 위협 감지 | `text`, `userId`, `elapsed` + 테스트 버전이면 `category`(욕설/위협), `confidence` |

```
{"type":"safe","text":"화장실 어디예요","elapsed":0.002}
{"type":"threat","text":"너 죽여버린다","userId":"010-1234-5678","category":"위협","confidence":0.93,"elapsed":0.004}
```

- `text`는 앞뒤 공백을 뗀 전사문입니다. `elapsed`는 판정에 걸린 시간(초)입니다.
- 욕설도 `threat`로 묶습니다. 무엇이었는지는 테스트 버전의 `category`로 구분합니다.

## 분류기

세 가지가 있습니다. **현재 기본값은 규칙 사전 단독**이고, 모델은 `-WithModel`로 켭니다.

| 분류기 | 쓰는 때 | 성격 |
|---|---|---|
| `KeywordClassifier` | 모델이 없을 때 | `lexicon.py`의 정규식 규칙. 적어둔 표현만 잡는다 |
| `ModelClassifier` | `THREAT_HYBRID=0` | 파인튜닝한 KcELECTRA |
| `HybridClassifier` | 기본값 | 둘 중 더 위험하게 본 쪽을 택한다 |

병행하는 이유는 둘이 놓치는 지점이 다르기 때문입니다. 모델은 처음 보는 표현·은어에 강하지만
학습 데이터(온라인 대화)에 드물었던 **간접 위협**을 확신도 0.98로 정상이라고 단언합니다.

```
가만 안 둬 너          모델 normal(0.99) → 병행 threat(0.85)
네 가족들 다 알아낼거야  모델 normal(0.98) → 병행 threat(0.90)
집앞으로 찾아갈게       모델 normal(0.98) → 병행 threat(0.85)
```

반대로 규칙 사전은 적어두지 않은 표현을 전혀 못 잡습니다. 안전 알람이므로 둘 중 하나라도
유해로 보면 알람을 보냅니다. 대규모 데이터에서 치르는 비용은 작습니다 — 아래 test셋
35,756문장 중 사전이 모델 판정을 덮어쓴 것은 46건(0.13%)뿐입니다.

### 어느 쪽을 쓸지 — 실측 비교

같은 test셋 35,756문장에서 재현율(놓치지 않고 잡아낸 비율)입니다.

| 구성 | 위협 recall | 욕설 recall | 비고 |
|---|---|---|---|
| **규칙 사전 단독 (현재 기본값)** | **0.083** | **0.013** | 정밀도는 높지만(위협 0.80) 거의 다 놓친다 |
| 모델 + 사전 병행 (`-WithModel`) | 0.773 | 0.874 | |

사전은 규칙 28개(위협 18 + 욕설 10)가 전부라, 적어두지 않은 표현에는 무력합니다. 위협
2,862건 중 237건만 잡습니다. 반대로 모델은 넓게 잡지만 AIHub가 정상으로 라벨링한 간접
위협("가만 안 둬")을 못 잡습니다. 둘은 서로 다른 구멍을 메웁니다.

현재 사전 단독으로 둔 것은 **모델 없이 먼저 테스트해보기 위한 선택**이며, 커버리지가
위와 같이 낮다는 점을 전제로 운영해야 합니다.

### 왜 모델만으로는 간접 위협을 못 잡나

모델 성능 문제가 아니라 **라벨 정의가 우리 현장과 다르기** 때문입니다. AIHub 코퍼스
451,110문장을 뒤져보면:

| 표현 | 등장 횟수 | 위협 라벨 | 정상(IMMORAL_NONE) 라벨 |
|---|---|---|---|
| 가만 안 둬 | 15 | 6.7% | 46.7% |
| 찾아간다 | 8 | 12.5% | 75.0% |
| 두고보자 | 65 | 4.6% | 76.9% |

```
거짓말이면 가만 안둬               → IMMORAL_NONE (정상)
너 한번만 더 그 말하면 가만 안둔다  → IMMORAL_NONE (정상)
```

온라인 대화에서 친구끼리 하는 "가만 안 둬"는 비윤리가 아닙니다. 그러나 민원인이 글라스
착용 직원에게 하면 알려야 할 위협입니다. 이 데이터로 재학습하는 한 모델 단독으로는
해결되지 않으며, 현장 전사문을 모아 우리 기준으로 라벨링하는 것이 근본 해결입니다.

## 모델 학습

### 1) 데이터 준비 (AIHub 텍스트 윤리검증 데이터, 2021)

[AIHub 텍스트 윤리검증 데이터](https://www.aihub.or.kr/aihubdata/data/view.do?dataSetSn=558)를 받으면
`1.AI 모델 소스코드.zip` 안에 라벨링 데이터(451,110문장)가 함께 들어 있습니다. 별도 데이터 신청이
필요 없습니다. 압축을 풀고 변환합니다.

```bash
python -m threat_server.prepare_aihub --src <압축푼경로>/data --out data
```

원본의 7종 다중 라벨을 3분류로 좁힙니다.

```
threat ← VIOLENCE, CRIME
abuse  ← ABUSE, HATE, SEXUAL, DISCRIMINATION
normal ← IMMORAL_NONE
CENSURE(비난) → 심각도 2.0 이상만 abuse, 미만은 학습에서 제외 (--censure severe, 기본값)
```

비난은 전체의 25%인데 "사회성이 얼마나 떨어지면 그러냐" 같은 가벼운 투정부터 "곱게 죽어라"까지
폭이 넓습니다. 전부 욕설로 묶으면 학습 데이터의 절반이 알람 대상이 되고, 그렇게 배운 모델은
관제실에 알람을 쏟아붓습니다. 애매한 구간은 normal로 끌어오지 않고 버립니다 — 가벼운 비난을
normal로 가르치면 진짜 폭언의 경계까지 무뎌지기 때문입니다.

중복 문장, 라벨이 엇갈리는 문장, train과 val/test에 겹치는 문장도 함께 제거합니다.

| 파일 | 행 수 | normal | abuse | threat |
|---|---|---|---|---|
| train.csv | 273,507 | 57.1% | 35.8% | 7.0% |
| val.csv | 31,023 | 58.4% | 34.5% | 7.1% |
| test.csv | 35,756 | 52.8% | 39.2% | 8.0% |

### 2) 학습

```bash
python -m threat_server.train --data data/train.csv --output models/threat-kcelectra     --epochs 3 --batch-size 32 --class-weights
```

- 기본 모델: `beomi/KcELECTRA-base-v2022` (한국어 댓글로 사전학습해 욕설·구어체에 강함)
- `--class-weights`는 꼭 켜세요. threat이 전체의 7%뿐이라 가중치 없이 학습하면 모델이 threat을
  아예 예측하지 않는 쪽으로 쏠립니다 (실측: threat F1 0.000)
- RTX 5070 Ti 기준 3 epoch에 14분, GPU 메모리 3.6 GB

### 3) 평가와 임계값 결정

```bash
python -m threat_server.evaluate --model models/threat-kcelectra --data data/test.csv --hybrid
```

test셋 35,756문장 실측 (병행 기준, macro F1 0.863):

| 클래스 | precision | recall | F1 |
|---|---|---|---|
| normal | 0.929 | 0.945 | 0.937 |
| abuse | 0.898 | 0.874 | 0.886 |
| threat | 0.760 | 0.773 | 0.766 |

`THREAT_THRESHOLD`는 분류 리포트가 아니라 **임계값 표**를 보고 정합니다. 서버는 argmax 라벨이
아니라 "그 라벨의 확률이 임계값 이상인가"로 알람 여부를 가르기 때문입니다.

| 임계값 | 정밀도 | 위협 재현율 | 정상→알람 오탐률 |
|---|---|---|---|
| 0.7 | 0.949 | 0.869 | 4.2% |
| **0.8 (권장)** | 0.957 | 0.837 | **3.4%** |
| 0.9 | 0.968 | 0.773 | 2.3% |

이 데이터셋은 유해 문장이 47%지만 실제 현장은 대부분 정상 대화입니다. 그래서 중요한 것은
정밀도보다 맨 오른쪽 **오탐률**입니다 — 0.7이면 정상 발화 100건당 4건이 알람으로 갑니다.

## 테스트

```bash
python -m pytest threat_server -q
```

## 한계

- 앱은 호출어("코비야") 뒤 질문만 녹음해 서버로 보냅니다. 호출어 없이 들어오는 폭언까지 감지하려면 상시 녹음·전사 흐름이 따로 필요합니다
- 규칙 사전의 확신도는 규칙에 매겨둔 가중치이지 모델 확률이 아닙니다. 병행 모드에서 사전이
  덮어쓴 판정의 확신도를 임계값과 비교할 때 이 점을 감안해야 합니다
- 학습 데이터는 **온라인 대화체**입니다. 현장에서 들어오는 말은 Whisper가 받아쓴 **구어체**이고
  전사 오류도 섞입니다("가만 안 둬" → "가만 안 부어"). 도메인 차이가 남아 있으며, 실제 현장
  전사문을 모아 재학습하면 가장 크게 개선될 지점입니다
- `control_server.py`는 메모리에만 저장하는 임시 수신 서버입니다. 실제 관제 시스템이 정해지면 `CONTROL_SERVER_URL`만 바꾸면 됩니다
