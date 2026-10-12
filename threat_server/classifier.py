"""전사문을 정상(normal) / 욕설(abuse) / 위협(threat) 3가지로 분류한다."""
from dataclasses import dataclass
from typing import Protocol

from . import lexicon

LABELS = ("normal", "abuse", "threat")
LABEL_KO = {"normal": "정상", "abuse": "욕설", "threat": "위협"}


@dataclass(frozen=True)
class Prediction:
    label: str          # LABELS 중 하나
    confidence: float   # 해당 라벨의 확률 (0~1)

    @property
    def is_harmful(self) -> bool:
        return self.label != "normal"


class Classifier(Protocol):
    def predict(self, text: str) -> Prediction: ...


class ModelClassifier:
    """train.py로 파인튜닝한 모델(KcELECTRA 등)로 분류한다."""

    def __init__(self, model_dir: str, device: str | None = None, max_length: int = 128):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(self.device).eval()
        self.max_length = max_length
        # 학습할 때 저장한 id2label을 따른다. LABELS와 다르면 잘못된 모델이다.
        self.id2label = {int(k): v for k, v in self.model.config.id2label.items()}
        unknown = set(self.id2label.values()) - set(LABELS)
        if unknown:
            raise ValueError(f"모델 라벨 {sorted(unknown)}은(는) {LABELS}에 없습니다")

    def predict(self, text: str) -> Prediction:
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True,
                                max_length=self.max_length).to(self.device)
        with self._torch.no_grad():
            probs = self.model(**inputs).logits.softmax(dim=-1)[0]
        idx = int(probs.argmax())
        return Prediction(self.id2label[idx], float(probs[idx]))


class KeywordClassifier:
    """규칙 사전(lexicon.py) 기반 분류기. 학습된 모델이 준비되기 전까지 쓴다.

    확신도는 걸린 규칙에 매겨둔 가중치이지 모델이 낸 확률이 아니다. 사전에 없는 표현은
    전혀 잡지 못하므로 실제 운영은 train.py로 학습한 ModelClassifier를 써야 한다.
    """

    def predict(self, text: str) -> Prediction:
        label, confidence = lexicon.score(text)
        return Prediction(label, confidence)

    def explain(self, text: str) -> dict[str, list[tuple[str, float]]]:
        """어떤 규칙이 걸렸는지 돌려준다 — 사전을 손볼 때 쓴다."""
        return lexicon.matches(text)


class HybridClassifier:
    """학습 모델과 규칙 사전을 함께 쓰고, 둘 중 더 위험한 쪽을 택한다.

    둘은 서로 다른 것을 놓친다. 모델은 처음 보는 표현과 은어에 강하지만, AIHub 학습
    데이터에 거의 없던 간접 위협("가만 안 둬", "집앞으로 찾아갈게")을 확신도 0.98로
    정상이라고 단언한다. 사전은 그런 화법을 정확히 잡지만 적어두지 않은 표현은 전혀 못 잡는다.

    안전 알람이므로 둘 중 하나라도 유해로 보면 알람을 보낸다. 다만 '무조건 합집합'은 아니다.
    사전은 정규식이라 확신도가 가중치일 뿐이어서, 모델이 더 높은 확신으로 같은 판정을
    내리면 모델 쪽 수치를 쓴다. 이렇게 해야 임계값 조절이 모델 확률 기준으로 일관된다.
    """

    # threat > abuse > normal 순으로 위험하다
    _RANK = {"normal": 0, "abuse": 1, "threat": 2}

    def __init__(self, model_dir: str, device: str | None = None, max_length: int = 128):
        self.model = ModelClassifier(model_dir, device, max_length)
        self.lexicon = KeywordClassifier()

    def predict(self, text: str) -> Prediction:
        m = self.model.predict(text)
        r = self.lexicon.predict(text)
        if self._RANK[r.label] > self._RANK[m.label]:
            return r                      # 모델이 놓친 것을 사전이 잡은 경우
        if r.label == m.label and r.label != "normal":
            return m if m.confidence >= r.confidence else r
        return m

    def explain(self, text: str) -> dict:
        return {"model": self.model.predict(text), "lexicon": self.lexicon.explain(text)}


def load_classifier(model_dir: str | None, hybrid: bool = True) -> Classifier:
    """모델 폴더가 있으면 모델(기본은 사전 병행), 없으면 사전만 쓴다."""
    if not model_dir:
        return KeywordClassifier()
    return HybridClassifier(model_dir) if hybrid else ModelClassifier(model_dir)
