from fastapi.testclient import TestClient

from threat_server.app import create_app
from threat_server.classifier import KeywordClassifier, Prediction
from threat_server.service import ThreatDetector
from threat_server.users import UserStore


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
    users = UserStore(":memory:")
    users.upsert("dev-1", "홍길동")
    return ThreatDetector(FixedClassifier(label, confidence), RecordingSender(), users, threshold)


def test_prod_alert_has_name_but_no_category_or_confidence():
    det = detector().check("dev-1", "욕설 문장", "prod")
    assert det.harmful
    assert det.alert["deviceId"] == "dev-1"
    assert det.alert["userName"] == "홍길동"
    assert det.alert["transcript"] == "욕설 문장"
    assert det.alert["variant"] == "prod"
    assert "category" not in det.alert and "confidence" not in det.alert


def test_test_alert_has_category_and_confidence():
    det = detector("threat", 0.88).check("dev-1", "위협 문장", "test")
    assert det.alert["category"] == "위협"
    assert det.alert["confidence"] == 0.88


def test_unregistered_device_alert_has_no_name():
    det = detector().check("dev-unknown", "욕설 문장", "prod")
    assert det.harmful and det.alert["userName"] is None


def test_below_threshold_or_normal_sends_nothing():
    assert not detector("abuse", 0.5).check("dev-1", "애매한 문장", "test").harmful
    assert detector("normal", 0.99).check("dev-1", "안녕하세요", "test").alert is None
    assert not detector().check("dev-1", "   ", "prod").harmful


def test_unknown_variant_rejected():
    try:
        detector().check("dev-1", "문장", "beta")
    except ValueError:
        return
    raise AssertionError("ValueError가 나야 합니다")


def test_endpoint_sends_alert_in_background():
    d = detector("abuse", 0.95)
    client = TestClient(create_app(d))

    r = client.post("/api/threat/check", json={"deviceId": "dev-1", "text": "욕", "variant": "test"})
    assert r.json() == {"harmful": True, "category": "욕설", "confidence": 0.95}

    # 앱이 아직 userId 필드로 보내도 받는다
    r = client.post("/api/threat/check", json={"userId": "dev-2", "text": "욕", "variant": "prod"})
    assert r.json() == {"harmful": True}

    assert [(a["deviceId"], a["userName"]) for a in d.sender.sent] == [("dev-1", "홍길동"), ("dev-2", None)]
    assert "confidence" not in d.sender.sent[1]


def test_user_register_lookup_and_rename():
    client = TestClient(create_app(detector()))

    assert client.get("/api/users/dev-new").status_code == 404

    r = client.put("/api/users/dev-new", json={"name": "  김철수 "})
    assert r.json() == {"deviceId": "dev-new", "name": "김철수"}
    assert client.get("/api/users/dev-new").json()["name"] == "김철수"

    client.put("/api/users/dev-new", json={"name": "김영희"})
    assert client.get("/api/users/dev-new").json()["name"] == "김영희"

    assert client.put("/api/users/dev-new", json={"name": "   "}).status_code == 422


def test_user_store_persists_to_file(tmp_path):
    path = str(tmp_path / "sub" / "users.db")
    UserStore(path).upsert("dev-9", "이순신")
    assert UserStore(path).get_name("dev-9") == "이순신"


def test_keyword_classifier():
    c = KeywordClassifier()
    assert c.predict("너 죽여 버린다").label == "threat"
    assert c.predict("씨 발 진짜").label == "abuse"
    assert c.predict("화장실 어디예요").label == "normal"
