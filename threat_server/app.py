"""욕설·위협 감지 서버.

실행: uvicorn threat_server.app:create_app --factory --host 0.0.0.0 --port 8002

음성 서버(/api/transcribe)에 바로 붙이려면 create_router()를 include_router로 넣거나,
전사 직후 ThreatDetector.check() / send_alert()를 직접 부르면 된다.
"""
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException, Path
from pydantic import AliasChoices, BaseModel, Field, StringConstraints

from .alert import AlertSender
from .classifier import LABEL_KO, load_classifier
from .config import load_settings
from .service import ThreatDetector
from .users import UserStore

log = logging.getLogger(__name__)

DeviceId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
UserName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=50)]


class CheckRequest(BaseModel):
    # 앱이 아직 userId로 보내는 동안은 userId도 받는다
    deviceId: DeviceId = Field(validation_alias=AliasChoices("deviceId", "userId"))
    text: str
    variant: Literal["test", "prod"] = "prod"


class CheckResponse(BaseModel):
    harmful: bool
    # 테스트 버전 응답에만 채운다
    category: str | None = None
    confidence: float | None = None


class UserRegister(BaseModel):
    name: UserName


class UserInfo(BaseModel):
    deviceId: str
    name: str


def build_detector() -> ThreatDetector:
    s = load_settings()
    if not s.model_dir:
        log.warning("THREAT_MODEL_DIR 미설정 — 개발용 KeywordClassifier로 동작합니다")
    return ThreatDetector(load_classifier(s.model_dir),
                          AlertSender(s.control_url, s.alert_timeout),
                          UserStore(s.user_db_path), s.threshold)


def create_router(detector: ThreatDetector) -> APIRouter:
    router = APIRouter()
    users = detector.users

    @router.post("/api/threat/check", response_model=CheckResponse, response_model_exclude_none=True)
    def check(req: CheckRequest, background: BackgroundTasks) -> CheckResponse:
        det = detector.check(req.deviceId, req.text, req.variant)
        if det.harmful:
            # 관제 서버가 느려도 폰 응답은 바로 돌려준다
            background.add_task(detector.send_alert, det)
        if req.variant == "test":
            return CheckResponse(harmful=det.harmful,
                                 category=LABEL_KO[det.prediction.label],
                                 confidence=round(det.prediction.confidence, 4))
        return CheckResponse(harmful=det.harmful)

    # 첫 설치 때 입력한 이름을 등록한다. 같은 기기 ID로 다시 부르면 이름을 바꾼다.
    @router.put("/api/users/{device_id}", response_model=UserInfo)
    def register_user(device_id: Annotated[DeviceId, Path()], body: UserRegister) -> UserInfo:
        users.upsert(device_id, body.name)
        return UserInfo(deviceId=device_id, name=body.name)

    # 재설치 후 앱이 기기 ID로 이름을 되찾는다. 없으면 404 → 앱이 이름을 다시 입력받는다.
    @router.get("/api/users/{device_id}", response_model=UserInfo)
    def get_user(device_id: Annotated[DeviceId, Path()]) -> UserInfo:
        name = users.get_name(device_id)
        if name is None:
            raise HTTPException(status_code=404, detail="등록되지 않은 기기입니다")
        return UserInfo(deviceId=device_id, name=name)

    return router


def create_app(detector: ThreatDetector | None = None) -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    app = FastAPI(title="Threat Detect Server")
    app.include_router(create_router(detector or build_detector()))

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
