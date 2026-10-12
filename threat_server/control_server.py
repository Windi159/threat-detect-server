"""관제 서버 (임시 수신용). 실제 관제 시스템이 정해지면 그쪽 주소로 CONTROL_SERVER_URL만 바꾼다.

실행: uvicorn threat_server.control_server:app --host 0.0.0.0 --port 9000
"""
import logging
from collections import deque
from datetime import datetime

from fastapi import FastAPI
from pydantic import BaseModel

log = logging.getLogger("control")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Control Server")
_alerts: deque[dict] = deque(maxlen=1000)


class Alert(BaseModel):
    userId: str
    transcript: str
    detectedAt: datetime
    variant: str
    # 테스트 버전 알람에만 들어온다
    category: str | None = None
    confidence: float | None = None


@app.post("/api/alerts")
def receive(alert: Alert) -> dict:
    record = alert.model_dump(mode="json", exclude_none=True)
    _alerts.appendleft(record)
    log.warning("[위협 알람] 사용자 %s: %s", alert.userId, record)
    return {"received": True}


@app.get("/api/alerts")
def recent(limit: int = 50) -> list[dict]:
    return list(_alerts)[:limit]
