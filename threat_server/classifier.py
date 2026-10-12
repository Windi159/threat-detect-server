"""전사문을 정상(normal) / 욕설(abuse) / 위협(threat) 3가지로 분류한다."""
from dataclasses import dataclass
from typing import Protocol

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
    """개발·연동 확인용 단어 사전 분류기. 학습된 모델이 준비되기 전까지만 쓴다.

    확신도는 사전에 걸리면 1.0, 아니면 정상 1.0으로 고정이라 실제 확률이 아니다.
    """

    THREAT_WORDS = ("죽여", "죽인다", "죽일", "죽을래", "패버", "때려", "찔러", "칼로",
                    "가만안둬", "가만안둔다", "불질러", "목졸")
    ABUSE_WORDS = ("씨발", "시발", "ㅅㅂ", "병신", "ㅂㅅ", "개새끼", "새끼", "지랄", "좆",
                   "미친놈", "미친년", "꺼져", "닥쳐", "엿먹어")

    def predict(self, text: str) -> Prediction:
        compact = "".join(text.split())
        if any(w in compact for w in self.THREAT_WORDS):
            return Prediction("threat", 1.0)
        if any(w in compact for w in self.ABUSE_WORDS):
            return Prediction("abuse", 1.0)
        return Prediction("normal", 1.0)


def load_classifier(model_dir: str | None) -> Classifier:
    return ModelClassifier(model_dir) if model_dir else KeywordClassifier()
