"""욕설·위협 감지 서버.

실행: uvicorn threat_server.app:create_app --factory --host 0.0.0.0 --port 8002

음성 서버(/api/transcribe)에 바로 붙이려면 create_router()를 include_router로 넣거나,
전사 직후 ThreatDetector.check() / send_alert()를 직접 부르면 된다.
"""
import logging
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, FastAPI
from pydantic import BaseModel, Field

from .alert import AlertSender
from .classifier import LABEL_KO, load_classifier
from .config import load_settings
from .service import ThreatDetector

log = logging.getLogger(__name__)


class CheckRequest(BaseModel):
    userId: str = Field(min_length=1)
    text: str
    variant: Literal["test", "prod"] = "prod"


class CheckResponse(BaseModel):
    harmful: bool
    # 테스트 버전 응답에만 채운다
    category: str | None = None
    confidence: float | None = None


def build_detector() -> ThreatDetector:
    s = load_settings()
    if not s.model_dir:
        log.warning("THREAT_MODEL_DIR 미설정 — 개발용 KeywordClassifier로 동작합니다")
    return ThreatDetector(load_classifier(s.model_dir),
                          AlertSender(s.control_url, s.alert_timeout), s.threshold)


def create_router(detector: ThreatDetector) -> APIRouter:
    router = APIRouter()

    @router.post("/api/threat/check", response_model=CheckResponse, response_model_exclude_none=True)
    def check(req: CheckRequest, background: BackgroundTasks) -> CheckResponse:
        det = detector.check(req.userId, req.text, req.variant)
        if det.harmful:
            # 관제 서버가 느려도 폰 응답은 바로 돌려준다
            background.add_task(detector.send_alert, det)
        if req.variant == "test":
            return CheckResponse(harmful=det.harmful,
                                 category=LABEL_KO[det.prediction.label],
                                 confidence=round(det.prediction.confidence, 4))
        return CheckResponse(harmful=det.harmful)

    return router


def create_app(detector: ThreatDetector | None = None) -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    app = FastAPI(title="Threat Detect Server")
    app.include_router(create_router(detector or build_detector()))

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
