"""욕설·위협 감지 서버.

실행: uvicorn threat_server.app:create_app --factory --host 0.0.0.0 --port 8002

STT 서버가 전사문을 POST /api/threat/check로 보내면, 판정 결과를 NDJSON 한 줄로 돌려준다.
줄 형식은 STT 서버의 /ws/live 메시지와 같은 {"type": ..., "text": ...} 구조다.

  정상: {"type":"safe","text":"<전사문>","elapsed":0.004}
  위협: {"type":"threat","text":"<전사문>","userId":"...","elapsed":0.004}
        테스트(test) 버전이면 "category"(욕설/위협)와 "confidence"가 더 붙는다.

욕설도 "threat"로 묶는다. 둘 다 착용자를 보호해야 하는 상황이라 STT 서버의 처리는 같다.
"""
import json
import logging
import time
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, FastAPI, Response
from pydantic import BaseModel, Field

from .alert import AlertSender
from .classifier import LABEL_KO, load_classifier
from .config import load_settings
from .service import ThreatDetector

log = logging.getLogger(__name__)

NDJSON = "application/x-ndjson"


class CheckRequest(BaseModel):
    userId: str = Field(min_length=1)
    text: str
    variant: Literal["test", "prod"] = "prod"


def build_detector() -> ThreatDetector:
    s = load_settings()
    if not s.model_dir:
        log.warning("THREAT_MODEL_DIR 미설정 — 개발용 KeywordClassifier로 동작합니다")
    return ThreatDetector(load_classifier(s.model_dir, s.hybrid),
                          AlertSender(s.control_url, s.alert_timeout), s.threshold)


def ndjson_line(obj: dict) -> Response:
    return Response(json.dumps(obj, ensure_ascii=False) + "\n", media_type=NDJSON)


def create_router(detector: ThreatDetector, alert_enabled: bool = False) -> APIRouter:
    router = APIRouter()

    @router.post("/api/threat/check")
    def check(req: CheckRequest, background: BackgroundTasks) -> Response:
        started = time.perf_counter()
        det = detector.check(req.userId, req.text, req.variant)
        elapsed = round(time.perf_counter() - started, 3)
        text = req.text.strip()

        if not det.harmful:
            return ndjson_line({"type": "safe", "text": text, "elapsed": elapsed})

        log.warning("위협 감지: userId=%s %s(%.3f) '%s'", req.userId,
                    LABEL_KO[det.prediction.label], det.prediction.confidence, text)
        if alert_enabled:
            # 관제 서버가 느려도 STT 서버 응답은 바로 돌려준다
            background.add_task(detector.send_alert, det)

        line = {"type": "threat", "text": text, "userId": req.userId}
        if req.variant == "test":
            line["category"] = LABEL_KO[det.prediction.label]
            line["confidence"] = round(det.prediction.confidence, 4)
        line["elapsed"] = elapsed
        return ndjson_line(line)

    return router


def create_app(detector: ThreatDetector | None = None, alert_enabled: bool | None = None) -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    if alert_enabled is None:
        alert_enabled = load_settings().alert_enabled
    if not alert_enabled:
        log.info("관제 서버 알람 꺼짐 (CONTROL_ALERT_ENABLED=1로 켠다)")
    app = FastAPI(title="Threat Detect Server")
    app.include_router(create_router(detector or build_detector(), alert_enabled))

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
