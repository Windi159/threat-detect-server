# GlassAssist 음성 파이프라인 — 인수인계

다른 PC에서 이어서 작업하기 위한 문서입니다. 2026-10-12 기준.

## 전체 그림

```
글라스(Glasses_0393) ──SCO 마이크──┐
                                   │
                    폰 S23+ GlassAssist 앱
                      "코비야" 웨이크워드 (온디바이스 TC-ResNet)
                      질문 녹음 (AudioRecord 16 kHz)
                                   │
                  Tailscale HTTPS  │ POST /api/transcribe
                                   ▼
        PC(desktop-horuhm4) :8000  Whisper large-v3-turbo (CUDA fp16)
                                   │ 전사문
                      ┌────────────┴────────────┐
                      │ (배경 작업)              │ (응답)
                      ▼                         ▼
          :8002 욕설·위협 감지              폰 앱
          KcELECTRA + 규칙 사전                │ 에코 모드면 TTS로 되읽기
                      │ 유해 + 확신도≥0.8      │ 아니면 LLM /chat 으로
                      ▼                         ▼
          :9000 관제 서버 (알람)          글라스 스피커 (TTS)
```

## 저장소 세 개

| 위치 | GitHub | 브랜치 | 내용 |
|---|---|---|---|
| `D:\whisper_tailscale` | **없음 (로컬 전용)** | — | Whisper STT 서버 + PWA |
| `D:\post_sh-t` | `Windi159/post_sh-t` (비공개) | `feature/whisper-stt` | 안드로이드 앱 (Kotlin) |
| `D:\threat-detect-server` | `Windi159/threat-detect-server` (공개) | `main` | 욕설·위협 감지 서버 |

> `whisper_tailscale`는 아직 git 저장소가 아닙니다. 다른 PC로 옮기려면 폴더를 복사하거나
> 저장소로 만들어 올려야 합니다. (`.venv`, `logs`, `static/*.apk`, `test_sample.wav` 제외)

## 1. Whisper STT 서버 (`D:\whisper_tailscale`)

### 설치·실행

```powershell
.\scripts\setup.ps1                 # uv로 Python 3.12 venv + 의존성
.\scripts\start.ps1                 # 수동 실행
.\scripts\install_autostart.ps1     # 로그인 시 자동 실행 (작업 스케줄러 "WhisperSTT Server")
```

- pip만 쓸 경우 `requirements.txt` / `requirements.lock.txt` 참고 (Python 3.11~3.12만 가능, ctranslate2가 3.13 미지원)
- CUDA Toolkit 설치 불필요 — `server/cuda_dlls.py`가 pip으로 깐 cuBLAS/cuDNN DLL 경로를 등록합니다
- 로그: `logs/server_<시각>.err.log` (현재 파일 경로는 `logs/current.txt`)

### 엔드포인트

| 경로 | 용도 |
|---|---|
| `GET /health`, `/api/health` | 상태 확인 (앱 연결 표시등도 이 경로를 씁니다) |
| `POST /api/transcribe` | 오디오 → 텍스트. 폼 필드: `file`, `language`, `task`, `beam_size`, `vad`, `initial_prompt`, `userId`, `variant` |
| `WS /ws/live` | 실시간 스트리밍 (16 kHz int16 PCM → partial/final JSON) |
| `GET /` | 휴대폰용 PWA (녹음 버튼 + 실시간 모드) |

### 설정 (`.env`)

| 키 | 현재값 | 설명 |
|---|---|---|
| `WHISPER_MODEL` | `large-v3-turbo` | |
| `WHISPER_DEVICE` / `WHISPER_COMPUTE` | `auto` / `float16` | CUDA 실패 시 CPU int8로 자동 폴백 |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | **포트를 바꾸면 `tailscale serve`도 다시 설정해야 합니다** |
| `THREAT_CHECK_URL` | `http://127.0.0.1:8002/api/threat/check` | 비우면 위협 검사 안 함 |
| `WHISPER_STUB_TEXT` | (비움) | 값이 있으면 전사를 건너뛰고 그 문장을 반환 (배선 점검용) |

## 2. 안드로이드 앱 (`D:\post_sh-t`, 브랜치 `feature/whisper-stt`)

main에는 아직 머지하지 않았습니다. 커밋 4개:

| 커밋 | 내용 |
|---|---|
| `bc7994e` | 질문 STT를 Whisper 서버로 전환 (`WhisperSttClient.kt` 신규), SpeechRecognizer는 폴백 |
| `c234da3` | HTTPS 주소로 전환, 글라스 마이크 레벨에 맞춰 말끝 감지 튜닝 |
| `7301102` | 실제 라우팅된 입력 장치 로그 (`getRoutedDevice`) |
| `96930b8` | 에코 모드 |
| `6050f4d` | MessageServer 본문을 UTF-8로 직접 읽기 |

### 주요 설정 (`UserPreferences.kt`)

| 키 | 기본값 | 설명 |
|---|---|---|
| `sttUrl` | `https://desktop-horuhm4.snowfinch-leaffish.ts.net` | Whisper 서버 |
| `apiUrl` | `http://175.196.239.135:8000` | LLM 서버 (`/chat`) — **현재 꺼져 있음** |
| `useWhisperStt` | `true` | false면 폰 내장 인식기 |
| `echoStt` | `false` | 인식 문장을 LLM 없이 글라스로 되읽기. **화면 길게 눌러 토글** |

> 기본값은 **앱 첫 설치 때만** 적용됩니다. 이후에는 SharedPreferences(`glassassist_prefs`)에
> 저장된 값이 쓰이므로, 주소를 바꾸려면 앱 데이터를 지우고 재설치해야 합니다.

### 빌드

```bash
# local.properties 에 sdk.dir 필요 (커밋 안 됨)
JAVA_HOME="D:/Android studio/jbr" ./gradlew :app:assembleDebug
```

APK는 265 MB(PyTorch Lite 포함)이고, 빌드 결과를 `whisper_tailscale/static/`에 복사해
`https://<서버>/GlassAssist-whisper-debug.apk` 로 폰에서 내려받게 해뒀습니다.

## 3. 욕설·위협 감지 서버 (`D:\threat-detect-server`, `main`)

```powershell
.\scripts\start.ps1            # 관제(9000) + 감지(8002), 모델+사전 병행, 임계값 0.8
.\scripts\start.ps1 -NoModel   # 규칙 사전만 (모델 로딩 없이)
```

### 모델은 저장소에 없습니다

511 MB라 `.gitignore`에 넣었습니다. 다른 PC에서는 다시 학습해야 하고, 없으면 자동으로
규칙 사전만 쓰게 됩니다(동작은 합니다).

```bash
# 1) AIHub「텍스트 윤리검증 데이터」(dataSetSn=558) 다운로드
#    "1.AI 모델 소스코드.zip" 안에 라벨 데이터 451,110문장이 들어 있습니다
python -m threat_server.prepare_aihub --src <압축푼경로>/data --out data
# 2) 학습 (RTX 5070 Ti 기준 14분)
python -m threat_server.train --data data/train.csv --output models/threat-kcelectra \
    --epochs 3 --batch-size 32 --class-weights
# 3) 평가 (임계값 표 포함)
python -m threat_server.evaluate --model models/threat-kcelectra --data data/test.csv --hybrid
```

학습에는 `torch`(CUDA 빌드, 약 2.5 GB) + `transformers` + `datasets` + `scikit-learn`이 필요합니다.

```bash
uv pip install torch --index-url https://download.pytorch.org/whl/cu128
uv pip install transformers datasets scikit-learn accelerate
```

### 실측 성능 (test셋 35,756문장, 병행 기준)

| 클래스 | precision | recall | F1 |
|---|---|---|---|
| normal | 0.929 | 0.945 | 0.937 |
| abuse | 0.898 | 0.874 | 0.886 |
| threat | 0.760 | 0.773 | 0.766 |

임계값 0.8에서 정밀도 0.957, 위협 재현율 0.837, 정상→알람 오탐률 3.4%.

## 네트워크 (Tailscale)

| 기기 | IP | 비고 |
|---|---|---|
| `desktop-horuhm4` | `100.90.50.47` | 이 PC. MagicDNS `desktop-horuhm4.snowfinch-leaffish.ts.net` |
| `s23` | `100.97.99.4` | 폰. 앱의 MessageServer가 `:8080`에서 대기 |
| `mukdesk` | `100.104.31.50` | 동료(jmlimjmlim07) PC |

- tailnet: `snowfinch-leaffish.ts.net` (소유자 `wontak12345@gmail.com`)
- `tailscale serve`가 HTTPS 443 → `127.0.0.1:8000`으로 프록시합니다. 설정은 재부팅 후에도 유지됩니다
- **HTTPS가 필요한 이유**: 브라우저는 HTTPS(또는 localhost)에서만 마이크를 허용합니다.
  직접 IP(`http://100.90.50.47:8000`)는 PC 방화벽의 python 차단 규칙에 막혀 있습니다
- 이 PC에는 tailnet 프로필이 2개 있습니다 (`tailscale switch --list`). 개인 tailnet이
  활성일 때만 위 주소가 동작합니다

### 폰으로 TTS 보내기

```bash
curl -X POST -H "Content-Type: text/plain; charset=UTF-8" \
     --data-binary "테스트입니다" http://100.97.99.4:8080/message
```

`Content-Type`을 빼면 NanoHTTPD가 본문을 폼 파라미터로 파싱해 빈 문자열이 TTS로 가고,
200 OK만 돌아와 성공처럼 보입니다. (커밋 `6050f4d`에서 서버 쪽은 고쳤지만 폰에 설치된
APK가 그 이전 버전이면 위 형식을 써야 합니다.)

## 지금 막혀 있는 것

1. **LLM 서버(`175.196.239.135:8000`)가 꺼져 있습니다.** ping도 안 닿습니다. 그래서 STT가
   성공해도 답변 음성이 안 나옵니다. 에코 모드를 켜면 LLM 없이도 글라스에서 소리를 들을 수 있지만,
   **에코 모드가 든 APK가 아직 폰에 설치되지 않았습니다** (USB 연결이 안 돼서).
   폰 브라우저로 `https://desktop-horuhm4.snowfinch-leaffish.ts.net/GlassAssist-whisper-debug.apk`
   를 받아 설치하면 됩니다.
2. 폰(`s23`)이 4일째 Tailscale 오프라인입니다.

## 다음에 할 만한 것

- **현장 전사문으로 재학습**: 학습 데이터는 온라인 대화체인데 실제 입력은 Whisper가 받아쓴
  구어체이고 전사 오류도 섞입니다(실측: "가만 안 둬" → "가만 안 부어"). 도메인 차이를 줄이는 것이
  가장 큰 개선 여지입니다
- 감지·관제 서버도 작업 스케줄러에 등록 (지금은 수동 실행)
- `whisper_tailscale`를 git 저장소로 만들기
- 앱 `feature/whisper-stt`를 main에 머지
- 상시 녹음: 지금은 "코비야" 뒤 질문만 전사하므로, 호출어 없이 들어오는 폭언은 감지하지 못합니다
