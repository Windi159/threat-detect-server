"""규칙 사전 판정 테스트.

오탐(정상인데 걸림)을 미탐(위협인데 놓침)만큼 비중 있게 다룬다. 관제 서버로 가는 알람이
잦아지면 아무도 보지 않게 되기 때문이다. NORMAL 목록은 실제로 예전 단어 사전이 잘못
잡았던 문장들이다.
"""

import pytest

from threat_server.classifier import KeywordClassifier
from threat_server.lexicon import normalize, score

# 현장(글라스 착용자 주변)에서 나올 법한 평범한 말들. 모두 normal이어야 한다.
NORMAL = [
    "안녕하세요 오늘 작업 내용 알려주세요",
    "화장실 어디예요",
    # 예전 사전이 욕설·위협으로 잘못 잡던 문장들
    "불 좀 꺼져 있나 확인해주세요",
    "전원이 꺼져서 다시 켰어요",
    "고양이 새끼가 귀여워요",
    "새끼손가락을 다쳤어요",
    "칼로리가 높은 음식이네요",
    "칼국수 먹으러 갑시다",
    "시간 죽이기 좋네요",
    "맛이 죽여주네요",
    "이 집 커피 죽여줍니다",
    "미친 듯이 바빴어요",
    "못을 때려 박으세요",
    "일 때려치우고 싶다",
    "서류를 뒤져봐야 알겠어요",
    "주머니를 뒤져서 찾았어요",
    "신발 끈을 졸라매세요",
    "집앞에 주차하면 됩니다",
    "내일 사무실로 찾아뵙겠습니다",
    "가위 좀 가져다 주세요",
    "망치로 못을 박았어요",
]

THREAT = [
    "너 죽여버린다",
    "진짜 죽여버릴거야",
    "너 오늘 죽었어 죽어버려",
    "칼로 찔러버린다",
    "칼 들고 찾아간다",
    "불질러버릴거야",
    "때려죽인다 진짜",
    "가만 안 둬 너",
    "가만두지 않겠다",
    "각오해라",
    "끝장내버릴거야",
    "박살내버린다",
    "네 가족들 다 알아낼거야",
    "집앞으로 찾아갈게",
    "목졸라 죽일거야",
]

ABUSE = [
    "씨발 진짜",
    "시발 뭐하는거야",
    "씨팔 짜증나네",
    "시1발 뭐냐",
    "야 이 병신아",
    "개새끼야",
    "저 새끼 뭐야",
    "지랄하지 마",
    "닥쳐 좀",
    "꺼져 이 자식아",
    "미친놈이네",
    "엿먹어라",
    "ㅅㅂ 뭐야",          # 타이핑 입력 대비 (Whisper 전사문에는 거의 안 나온다)
    "ㅂㅅ 아니야",
]


@pytest.mark.parametrize("text", NORMAL)
def test_normal_not_flagged(text):
    label, _ = score(text)
    assert label == "normal", f"오탐: {text!r} → {label}"


@pytest.mark.parametrize("text", THREAT)
def test_threat_detected(text):
    label, conf = score(text)
    assert label == "threat", f"미탐: {text!r} → {label}"
    assert conf >= 0.6


@pytest.mark.parametrize("text", ABUSE)
def test_abuse_detected(text):
    label, conf = score(text)
    assert label in ("abuse", "threat"), f"미탐: {text!r} → {label}"
    assert conf >= 0.7


def test_threat_wins_over_abuse():
    # 위협 문장에는 욕설이 섞이기 마련인데, 급한 쪽은 위협이다
    assert score("씨발 너 죽여버린다")[0] == "threat"


def test_alert_worthy_threats_clear_default_threshold():
    # 기본 THREAT_THRESHOLD=0.7. 명백한 위협은 알람이 나가야 한다.
    for text in ("너 죽여버린다", "칼로 찔러버린다", "가만 안 둬", "칼 들고 찾아간다"):
        assert score(text)[1] >= 0.7, text


def test_normalize_handles_spacing_and_repeats():
    assert normalize("죽 여 버 린 다!!") == "죽여버린다"
    assert normalize("죽어어어어") == "죽어"
    assert normalize("시1발") == "시발"


def test_classifier_uses_lexicon():
    c = KeywordClassifier()
    assert c.predict("너 죽여 버린다").label == "threat"
    assert c.predict("씨 발 진짜").label == "abuse"
    assert c.predict("화장실 어디예요").label == "normal"
    assert c.explain("너 죽여버린다")["threat"]


# --- 병행(Hybrid) 분류기 -------------------------------------------------------

class _StubModel:
    """학습 모델 없이 병행 규칙만 검증하기 위한 가짜 모델."""

    def __init__(self, label, confidence):
        self.pred = (label, confidence)

    def predict(self, text):
        from threat_server.classifier import Prediction
        return Prediction(*self.pred)


def _hybrid(model_label, model_conf):
    from threat_server.classifier import HybridClassifier, KeywordClassifier
    h = HybridClassifier.__new__(HybridClassifier)   # 모델 로딩을 건너뛴다
    h.model = _StubModel(model_label, model_conf)
    h.lexicon = KeywordClassifier()
    return h


def test_hybrid_lexicon_catches_what_model_misses():
    # 실제로 관측된 실패: 모델이 간접 위협을 확신도 0.99로 정상이라 했다
    h = _hybrid("normal", 0.99)
    assert h.predict("가만 안 둬 너").label == "threat"
    assert h.predict("집앞으로 찾아갈게").label == "threat"


def test_hybrid_keeps_model_when_model_is_more_severe():
    h = _hybrid("threat", 0.93)
    assert h.predict("사전에 없는 새로운 위협 표현").label == "threat"


def test_hybrid_prefers_higher_confidence_on_agreement():
    assert _hybrid("abuse", 0.99).predict("씨발 진짜").confidence == 0.99   # 모델 쪽이 높음
    assert _hybrid("abuse", 0.72).predict("씨발 진짜").confidence >= 0.95   # 사전 쪽이 높음


def test_hybrid_stays_normal_when_both_agree():
    h = _hybrid("normal", 0.97)
    assert h.predict("화장실 어디예요").label == "normal"
