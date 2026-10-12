"""욕설·위협 분류 모델 파인튜닝 (정상/욕설/위협 3분류).

데이터: CSV 또는 JSONL, 컬럼 text, label
  label 값은 normal / abuse / threat (또는 0 / 1 / 2)
  예) AIHub 한국어 욕설·혐오 데이터를 이 형식으로 변환해서 쓴다.

실행:
  python -m threat_server.train --data data/train.csv --output models/threat-kcelectra
"""
import argparse

import numpy as np

from .classifier import LABELS

LABEL2ID = {name: i for i, name in enumerate(LABELS)}


def to_label_id(value) -> int:
    if isinstance(value, str) and value in LABEL2ID:
        return LABEL2ID[value]
    idx = int(value)
    if idx not in range(len(LABELS)):
        raise ValueError(f"알 수 없는 라벨: {value!r}")
    return idx


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", required=True, help="학습 데이터 (.csv / .jsonl)")
    p.add_argument("--output", required=True, help="모델 저장 폴더 (THREAT_MODEL_DIR로 쓴다)")
    p.add_argument("--base-model", default="beomi/KcELECTRA-base-v2022")
    p.add_argument("--epochs", type=float, default=3)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--lr", type=float, default=3e-5)
    p.add_argument("--max-length", type=int, default=128)
    p.add_argument("--eval-ratio", type=float, default=0.1)
    p.add_argument("--class-weights", action="store_true",
                   help="클래스 빈도의 역수를 손실 가중치로 쓴다. threat이 전체의 7%%뿐이라 "
                        "가중치 없이 학습하면 threat을 아예 예측하지 않는 쪽으로 쏠린다.")
    args = p.parse_args()

    from datasets import load_dataset
    from sklearn.metrics import classification_report, f1_score
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                              DataCollatorWithPadding, Trainer, TrainingArguments)

    fmt = "json" if args.data.endswith(".jsonl") else "csv"
    ds = load_dataset(fmt, data_files=args.data)["train"]
    ds = ds.map(lambda r: {"text": str(r["text"]), "label": to_label_id(r["label"])})
    ds = ds.class_encode_column("label").train_test_split(
        test_size=args.eval_ratio, seed=42, stratify_by_column="label")

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    ds = ds.map(lambda b: tokenizer(b["text"], truncation=True, max_length=args.max_length), batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=len(LABELS),
        id2label=dict(enumerate(LABELS)), label2id=LABEL2ID)

    def metrics(eval_pred):
        preds = np.argmax(eval_pred.predictions, axis=-1)
        return {"macro_f1": f1_score(eval_pred.label_ids, preds, average="macro")}

    trainer_cls = Trainer
    if args.class_weights:
        import torch

        counts = np.bincount(ds["train"]["label"], minlength=len(LABELS))
        weights = torch.tensor(counts.sum() / (len(LABELS) * np.maximum(counts, 1)),
                               dtype=torch.float32)
        print("클래스 가중치:", dict(zip(LABELS, weights.tolist())))

        class WeightedTrainer(Trainer):
            def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
                labels = inputs.pop("labels")
                outputs = model(**inputs)
                loss = torch.nn.functional.cross_entropy(
                    outputs.logits, labels, weight=weights.to(outputs.logits.device))
                return (loss, outputs) if return_outputs else loss

        trainer_cls = WeightedTrainer

    trainer = trainer_cls(
        model=model,
        args=TrainingArguments(
            output_dir=args.output, num_train_epochs=args.epochs, learning_rate=args.lr,
            per_device_train_batch_size=args.batch_size, per_device_eval_batch_size=args.batch_size,
            eval_strategy="epoch", save_strategy="epoch", load_best_model_at_end=True,
            metric_for_best_model="macro_f1", save_total_limit=1, report_to=[]),
        train_dataset=ds["train"], eval_dataset=ds["test"],
        data_collator=DataCollatorWithPadding(tokenizer), compute_metrics=metrics)
    trainer.train()

    out = trainer.predict(ds["test"])
    print(classification_report(out.label_ids, np.argmax(out.predictions, axis=-1),
                                labels=list(range(len(LABELS))), target_names=list(LABELS), digits=3))
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)


if __name__ == "__main__":
    main()
