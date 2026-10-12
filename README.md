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
| `THREAT_MODEL_DIR` | (없음) | 학습한 모델 폴더. 없으면 `KeywordClassifier`(개발용) |
| `CONTROL_SERVER_URL` | `http://127.0.0.1:9000/api/alerts` | 관제 서버 알람 주소 |
| `THREAT_THRESHOLD` | `0.7` | 이 확신도 이상일 때만 알람 |
| `ALERT_TIMEOUT` | `3.0` | 관제 서버 요청 타임아웃(초) |

### 확인

```bash
curl -X POST localhost:8002/api/threat/check -H 'content-type: application/json' \
  -d '{"userId":"010-1234-5678","text":"너 죽여버린다","variant":"test"}'
# {"harmful":true,"category":"위협","confidence":1.0}
```

## 음성 서버(/api/transcribe)에 붙이기

앱([post_sh-t](https://github.com/Windi159/post_sh-t) `feature/threat-detect-server`)은 `/api/transcribe` 요청에 `userId`, `variant` 폼 필드를 함께 보냅니다.
음성 서버 코드에서 전사 직후 아래처럼 부르면 됩니다.

```python
from fastapi import BackgroundTasks, File, Form, UploadFile
from threat_server.app import build_detector

detector = build_detector()   # 서버 시작 시 한 번

@app.post("/api/transcribe")
def transcribe(background: BackgroundTasks, file: UploadFile = File(...),
               userId: str = Form("미설정"), variant: str = Form("prod"), ...):
    text = ...  # 기존 Whisper 전사
    det = detector.check(userId, text, variant if variant in ("test", "prod") else "prod")
    if det.harmful:
        background.add_task(detector.send_alert, det)   # 폰 응답을 늦추지 않는다
    ...  # 기존 응답 그대로
```

별도 프로세스로 둘 경우에는 음성 서버가 `POST /api/threat/check`를 호출하면 됩니다.

## 모델 학습

현재 서버의 few-shot 프롬프트 분류는 정확도가 낮아서, 3분류 전용 모델을 파인튜닝합니다.

```bash
# data/train.csv : text,label  (label = normal / abuse / threat 또는 0 / 1 / 2)
python -m threat_server.train --data data/train.csv --output models/threat-kcelectra
```

- 기본 모델: `beomi/KcELECTRA-base-v2022` (한국어 댓글로 사전학습해 욕설·구어체에 강함)
- 데이터 후보: AIHub 한국어 욕설/혐오표현 데이터. 위협 문장은 별도로 모아 `threat` 라벨을 붙여야 합니다
- 학습이 끝나면 검증셋 classification report를 출력합니다. `THREAT_THRESHOLD`는 이 결과를 보고 정합니다

## 테스트

```bash
python -m pytest threat_server -q
```

## 한계

- 앱은 호출어("코비야") 뒤 질문만 녹음해 서버로 보냅니다. 호출어 없이 들어오는 폭언까지 감지하려면 상시 녹음·전사 흐름이 따로 필요합니다
- `KeywordClassifier`는 연동 확인용입니다. 확신도가 항상 1.0이라 실제 확률이 아닙니다
- `control_server.py`는 메모리에만 저장하는 임시 수신 서버입니다. 실제 관제 시스템이 정해지면 `CONTROL_SERVER_URL`만 바꾸면 됩니다
