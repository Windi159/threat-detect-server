"""AIHub「텍스트 윤리검증 데이터」(2021) → train.py가 읽는 CSV(text,label)로 변환한다.

원본은 탭으로 나뉜 6개 컬럼이다.
    인덱스 \t 비윤리여부 \t 심각도 \t 판정인원 \t 라벨들 \t 문장
라벨은 쉼표로 이어 붙인 다중 라벨이고 순서는 일정하지 않다 (HATE,CENSURE / CENSURE,HATE).

7종 라벨을 우리가 쓰는 3분류로 좁힌다.

    threat ← VIOLENCE, CRIME            위해를 예고하거나 범죄를 부추기는 말
    abuse  ← ABUSE, HATE, SEXUAL, DISCRIMINATION
    normal ← IMMORAL_NONE

CENSURE(비난)는 따로 다룬다. 전체의 25%를 차지하는데 "사회성이 얼마나 떨어지면 그러냐"
같은 가벼운 투정부터 "곱게 죽어라"까지 폭이 넓다. 전부 욕설로 묶으면 학습 데이터의 절반이
알람 대상이 되고, 그렇게 배운 모델은 관제실에 알람을 쏟아붓는다. 기본값은 심각도
2.0 이상인 비난만 욕설로 본다(--censure severe).

사용:
    python -m threat_server.prepare_aihub --src D:/aihub_ethics/data --out data
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

THREAT_TAGS = frozenset({"VIOLENCE", "CRIME"})
ABUSE_TAGS = frozenset({"ABUSE", "HATE", "SEXUAL", "DISCRIMINATION"})
NONE_TAG = "IMMORAL_NONE"


def to_label(tags: set[str], severity: float, censure: str) -> str | None:
    """3분류 라벨을 정한다. None이면 학습에서 제외한다."""
    if NONE_TAG in tags:
        return "normal"
    if tags & THREAT_TAGS:
        return "threat"
    if tags & ABUSE_TAGS:
        return "abuse"
    if "CENSURE" in tags:
        if censure == "abuse":
            return "abuse"
        if censure == "severe":
            # 애매한 구간(심각도 2.0 미만)은 normal로 끌어오지 않고 아예 버린다.
            # 가벼운 비난을 normal로 가르치면 진짜 폭언의 경계까지 무뎌진다.
            return "abuse" if severity >= 2.0 else None
        return None  # drop
    return None


def parse(path: Path, censure: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    skipped = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                skipped += 1
                continue
            _, _, sev_raw, _, tag_raw, text = parts[:6]
            text = text.strip()
            if not text:
                skipped += 1
                continue
            try:
                severity = float(sev_raw) if sev_raw else 0.0
            except ValueError:
                severity = 0.0
            label = to_label(set(tag_raw.split(",")), severity, censure)
            if label:
                rows.append((text, label))
            else:
                skipped += 1
    print(f"  {path.name}: {len(rows)}행 사용, {skipped}행 제외")
    return rows


def dedup(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """같은 문장이 여러 번 나오면 첫 번째만 남긴다.

    라벨이 엇갈리는 중복은 둘 다 버린다. 같은 문장을 normal로도 abuse로도 가르치면
    그 경계만 흐려진다.
    """
    by_text: dict[str, set[str]] = {}
    order: list[str] = []
    for text, label in rows:
        if text not in by_text:
            by_text[text] = set()
            order.append(text)
        by_text[text].add(label)
    out = [(t, next(iter(by_text[t]))) for t in order if len(by_text[t]) == 1]
    conflict = sum(1 for t in order if len(by_text[t]) > 1)
    print(f"  중복 제거: {len(rows)} → {len(out)}행 (라벨 충돌로 버린 문장 {conflict}개)")
    return out


def write(rows: list[tuple[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)
    dist = Counter(label for _, label in rows)
    total = sum(dist.values())
    share = "  ".join(f"{k}={v}({v / total * 100:.1f}%)" for k, v in dist.most_common())
    print(f"  → {path}  {total}행   {share}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="AIHub data 폴더 (train/val/test 파일이 있는 곳)")
    ap.add_argument("--out", default="data", help="CSV를 쓸 폴더")
    ap.add_argument("--censure", choices=("severe", "abuse", "drop"), default="severe",
                    help="비난(CENSURE) 처리: severe=심각도 2.0 이상만 욕설(기본), "
                         "abuse=전부 욕설, drop=전부 제외")
    args = ap.parse_args()

    src, out = Path(args.src), Path(args.out)
    splits = {"train": "train.csv", "val": "val.csv", "test": "test.csv"}
    missing = [n for n in splits if not (src / n).exists()]
    if missing:
        sys.exit(f"원본 파일이 없습니다: {[str(src / n) for n in missing]}")

    print(f"변환 (CENSURE 처리: {args.censure})")
    parsed = {name: dedup(parse(src / name, args.censure)) for name in splits}

    # 평가가 부풀지 않도록 train에서 val/test와 겹치는 문장을 뺀다
    held = {t for name in ("val", "test") for t, _ in parsed[name]}
    before = len(parsed["train"])
    parsed["train"] = [(t, l) for t, l in parsed["train"] if t not in held]
    print(f"  train에서 val/test와 겹치는 {before - len(parsed['train'])}행 제거")

    for name, filename in splits.items():
        write(parsed[name], out / filename)


if __name__ == "__main__":
    main()
