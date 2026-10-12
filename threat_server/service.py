"""전사문 판정 → 알람 본문 생성. 음성 서버에서 직접 불러 써도 된다."""
from dataclasses import dataclass
from datetime import datetime

from .alert import VARIANTS, AlertSender, build_alert
from .classifier import Classifier, Prediction


@dataclass(frozen=True)
class Detection:
    prediction: Prediction
    harmful: bool             # 알람 대상인지 (욕설·위협 + 확신도 임계 이상)
    alert: dict | None        # harmful일 때만 관제 서버로 보낼 본문


class ThreatDetector:
    def __init__(self, classifier: Classifier, sender: AlertSender, threshold: float = 0.7):
        self.classifier = classifier
        self.sender = sender
        self.threshold = threshold

    def check(self, user_id: str, text: str, variant: str) -> Detection:
        if variant not in VARIANTS:
            raise ValueError(f"variant는 {VARIANTS} 중 하나여야 합니다: {variant!r}")
        text = text.strip()
        if not text:
            return Detection(Prediction("normal", 1.0), False, None)
        pred = self.classifier.predict(text)
        harmful = pred.is_harmful and pred.confidence >= self.threshold
        alert = build_alert(user_id, text, variant, pred, datetime.now().astimezone()) if harmful else None
        return Detection(pred, harmful, alert)

    def send_alert(self, detection: Detection) -> bool:
        return detection.alert is not None and self.sender.send(detection.alert)
