import json

from fastapi.testclient import TestClient

from threat_server.app import create_app
from threat_server.classifier import KeywordClassifier, Prediction
from threat_server.service import ThreatDetector


class FixedClassifier:
    def __init__(self, label: str, confidence: float):
        self.pred = Prediction(label, confidence)

    def predict(self, text: str) -> Prediction:
        return self.pred


class RecordingSender:
    def __init__(self):
        self.sent: list[dict] = []

    def send(self, payload: dict) -> bool:
        self.sent.append(payload)
        return True


def detector(label="abuse", confidence=0.93, threshold=0.7):
    return ThreatDetector(FixedClassifier(label, confidence), RecordingSender(), threshold)


def test_prod_alert_has_no_category_or_confidence():
    det = detector().check("010-1234-5678", "욕설 문장", "prod")
    assert det.harmful
    assert det.alert["userId"] == "010-1234-5678"
    assert det.alert["transcript"] == "욕설 문장"
    assert det.alert["variant"] == "prod"
    assert "category" not in det.alert and "confidence" not in det.alert


def test_test_alert_has_category_and_confidence():
    det = detector("threat", 0.88).check("010-1234-5678", "위협 문장", "test")
    assert det.alert["category"] == "위협"
    assert det.alert["confidence"] == 0.88


def test_below_threshold_or_normal_sends_nothing():
    assert not detector("abuse", 0.5).check("u", "애매한 문장", "test").harmful
    assert detector("normal", 0.99).check("u", "안녕하세요", "test").alert is None
    assert not detector().check("u", "   ", "prod").harmful


def test_unknown_variant_rejected():
    try:
        detector().check("u", "문장", "beta")
    except ValueError:
        return
    raise AssertionError("ValueError가 나야 합니다")


def ndjson(r) -> dict:
    assert r.headers["content-type"].startswith("application/x-ndjson")
    lines = r.text.splitlines()
    assert len(lines) == 1 and r.text.endswith("\n")
    obj = json.loads(lines[0])
    assert isinstance(obj.pop("elapsed"), float)
    return obj


def test_endpoint_returns_ndjson_threat_line():
    client = TestClient(create_app(detector("abuse", 0.95), alert_enabled=False))

    r = client.post("/api/threat/check", json={"userId": "010-1", "text": " 욕 ", "variant": "test"})
    assert ndjson(r) == {"type": "threat", "text": "욕", "userId": "010-1",
                         "category": "욕설", "confidence": 0.95}

    r = client.post("/api/threat/check", json={"userId": "010-2", "text": "욕", "variant": "prod"})
    assert ndjson(r) == {"type": "threat", "text": "욕", "userId": "010-2"}


def test_endpoint_returns_ndjson_safe_line():
    client = TestClient(create_app(detector("normal", 0.99), alert_enabled=False))
    r = client.post("/api/threat/check", json={"userId": "010-1", "text": "화장실 어디예요", "variant": "test"})
    assert ndjson(r) == {"type": "safe", "text": "화장실 어디예요"}


def test_alert_is_off_by_default_and_sent_when_enabled(monkeypatch):
    monkeypatch.delenv("CONTROL_ALERT_ENABLED", raising=False)
    off = detector("threat", 0.95)
    TestClient(create_app(off)).post("/api/threat/check", json={"userId": "010-1", "text": "위협"})
    assert off.sender.sent == []

    on = detector("threat", 0.95)
    TestClient(create_app(on, alert_enabled=True)).post(
        "/api/threat/check", json={"userId": "010-1", "text": "위협", "variant": "prod"})
    assert [a["userId"] for a in on.sender.sent] == ["010-1"]
    assert "confidence" not in on.sender.sent[0]


def test_keyword_classifier():
    c = KeywordClassifier()
    assert c.predict("너 죽여 버린다").label == "threat"
    assert c.predict("씨 발 진짜").label == "abuse"
    assert c.predict("화장실 어디예요").label == "normal"
