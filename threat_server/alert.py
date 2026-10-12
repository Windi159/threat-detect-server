"""관제 서버로 보내는 알람."""
import logging
from datetime import datetime

import httpx

from .classifier import LABEL_KO, Prediction

log = logging.getLogger(__name__)

VARIANTS = ("test", "prod")


def build_alert(user_id: str, transcript: str, variant: str,
                prediction: Prediction, detected_at: datetime) -> dict:
    """알람 본문을 만든다.

    일반(prod) 버전: 사용자 전화번호, 전사문, 시각만 보낸다.
    테스트(test) 버전: 위에 더해 분류(욕설/위협)와 모델 확신도를 보낸다.
    """
    payload = {
        "userId": user_id,
        "transcript": transcript,
        "detectedAt": detected_at.isoformat(timespec="seconds"),
        "variant": variant,
    }
    if variant == "test":
        payload["category"] = LABEL_KO[prediction.label]
        payload["confidence"] = round(prediction.confidence, 4)
    return payload


class AlertSender:
    def __init__(self, url: str, timeout: float = 3.0):
        self.url = url
        self.timeout = timeout

    def send(self, payload: dict) -> bool:
        try:
            resp = httpx.post(self.url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.error("관제 서버 알람 실패 (%s): %s", self.url, e)
            return False
        log.info("관제 서버 알람 전송: userId=%s", payload.get("userId"))
        return True
