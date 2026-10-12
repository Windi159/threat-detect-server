"""학습한 모델을 평가한다. 임계값(THREAT_THRESHOLD)을 정하는 것이 주 목적이다.

분류 리포트만으로는 운영 임계값을 못 정한다. 서버는 argmax 라벨이 아니라 "그 라벨의 확률이
임계값 이상인가"로 알람 여부를 가르기 때문이다(service.ThreatDetector). 그래서 임계값을
바꿔가며 알람 기준 정밀도·재현율이 어떻게 변하는지 함께 출력한다.

실행:
    python -m threat_server.evaluate --model models/threat-kcelectra --data data/test.csv
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

import numpy as np

from .classifier import LABELS

LABEL2ID = {name: i for i, name in enumerate(LABELS)}


def load(path: Path) -> tuple[list[str], np.ndarray]:
    texts, labels = [], []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            texts.append(row["text"])
            labels.append(LABEL2ID[row["label"]])
    return texts, np.array(labels)


def predict(model_dir: str, texts: list[str], batch_size: int, max_length: int) -> np.ndarray:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(device).eval()
    # 저장된 id2label이 LABELS와 순서가 다르면 아래 모든 수치가 조용히 틀어진다
    saved = [model.config.id2label[i] for i in range(len(LABELS))]
    if saved != list(LABELS):
        sys.exit(f"모델 라벨 순서가 다릅니다: {saved} != {list(LABELS)}")

    out = np.empty((len(texts), len(LABELS)), dtype=np.float32)
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = tok(texts[i:i + batch_size], return_tensors="pt", padding=True,
                        truncation=True, max_length=max_length).to(device)
            out[i:i + batch_size] = model(**batch).logits.softmax(-1).cpu().numpy()
            if i % (batch_size * 50) == 0:
                print(f"\r  추론 {i + len(batch['input_ids'])}/{len(texts)}", end="", flush=True)
    print()
    return out


def threshold_table(probs: np.ndarray, gold: np.ndarray) -> None:
    """서버가 실제로 쓰는 규칙(argmax가 유해 + 그 확률 >= 임계값)으로 알람 품질을 계산한다."""
    pred = probs.argmax(1)
    top = probs.max(1)
    gold_harmful = gold != LABEL2ID["normal"]
    gold_threat = gold == LABEL2ID["threat"]

    print("\n임계값별 알람 품질 (알람 = 유해로 분류 + 확신도 >= 임계값)")
    print(f"{'임계값':>6} {'알람수':>8} {'정밀도':>7} {'재현율':>7} {'위협재현율':>10} {'오탐(정상→알람)':>15}")
    for th in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
        alert = (pred != LABEL2ID["normal"]) & (top >= th)
        n = int(alert.sum())
        if n == 0:
            print(f"{th:>6.2f} {0:>8}  (알람 없음)")
            continue
        precision = float((alert & gold_harmful).sum()) / n
        recall = float((alert & gold_harmful).sum()) / int(gold_harmful.sum())
        threat_recall = float((alert & gold_threat).sum()) / int(gold_threat.sum())
        false_alarm = float((alert & ~gold_harmful).sum()) / int((~gold_harmful).sum())
        print(f"{th:>6.2f} {n:>8} {precision:>7.3f} {recall:>7.3f} {threat_recall:>10.3f} "
              f"{false_alarm:>14.1%}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", required=True, help="text,label 컬럼의 CSV")
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--max-length", type=int, default=128)
    ap.add_argument("--errors", type=int, default=5, help="유형별로 보여줄 오분류 예시 수")
    ap.add_argument("--hybrid", action="store_true",
                    help="규칙 사전을 함께 적용해 평가한다 (운영 기본값과 같은 조건)")
    args = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    texts, gold = load(Path(args.data))
    print(f"{args.data}: {len(texts)}문장  {dict(Counter(LABELS[i] for i in gold))}")
    probs = predict(args.model, texts, args.batch_size, args.max_length)

    if args.hybrid:
        # HybridClassifier와 같은 규칙: 사전이 더 위험하다고 보면 그 판정으로 바꾼다.
        # 확률 벡터로 비교해야 하므로, 덮어쓸 때는 사전 가중치를 그 라벨의 확률로 넣는다.
        from .lexicon import score as lexicon_score

        rank = {"normal": 0, "abuse": 1, "threat": 2}
        overridden = Counter()
        for i, text in enumerate(texts):
            label, conf = lexicon_score(text)
            if rank[label] > rank[LABELS[int(probs[i].argmax())]]:
                overridden[f"{LABELS[int(probs[i].argmax())]}→{label}"] += 1
                probs[i] = (1.0 - conf) / (len(LABELS) - 1)
                probs[i][LABEL2ID[label]] = conf
        print(f"규칙 사전이 덮어쓴 건수: {sum(overridden.values())} {dict(overridden)}")

    pred = probs.argmax(1)

    from sklearn.metrics import classification_report, confusion_matrix

    print("\n" + classification_report(gold, pred, labels=range(len(LABELS)),
                                       target_names=list(LABELS), digits=3))
    print("혼동 행렬 (행=정답, 열=예측)")
    print(f"{'':>8}" + "".join(f"{n:>9}" for n in LABELS))
    for i, row in enumerate(confusion_matrix(gold, pred, labels=range(len(LABELS)))):
        print(f"{LABELS[i]:>8}" + "".join(f"{v:>9}" for v in row))

    threshold_table(probs, gold)

    if args.errors:
        print("\n오분류 예시")
        for g in range(len(LABELS)):
            for p in range(len(LABELS)):
                if g == p:
                    continue
                idx = np.where((gold == g) & (pred == p))[0]
                if not len(idx):
                    continue
                print(f"\n  정답 {LABELS[g]} → 예측 {LABELS[p]} ({len(idx)}건)")
                for i in idx[:args.errors]:
                    print(f"    [{probs[i][p]:.2f}] {texts[i][:70]}")


if __name__ == "__main__":
    main()
