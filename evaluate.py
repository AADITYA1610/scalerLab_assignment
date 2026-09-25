"""Exact-span evaluation on manually labelled real-document paragraphs."""
import csv
import json
import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from docx import Document
from redact import paragraphs

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "input" / "Red Herring Prospectus.docx"
LOG = ROOT / "output" / "detections.csv"

def safe_ratio(numerator, denominator):
    return numerator / denominator if denominator else None

def fmt(value):
    return f"{value:.3f}" if value is not None else "N/A"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--gold", type=Path, required=True,
        help="Label file to evaluate; samples used for tuning are regression checks",
    )
    parser.add_argument("--log", type=Path, default=LOG)
    args = parser.parse_args()
    source = dict((loc, p.text) for loc, p in paragraphs(Document(INPUT)))
    cases = json.loads(args.gold.read_text(encoding="utf-8"))
    predictions = defaultdict(set)
    with args.log.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            predictions[row["location"]].add(
                (row["type"], int(row["start"]), int(row["end"]))
            )
    counts = defaultdict(Counter)
    correct_characters = 0
    total_characters = 0
    errors = []
    for case in cases:
        loc = case["location"]
        text = source[loc]
        gold = set()
        expected = Counter(tuple(label) for label in case["labels"])
        used = Counter()
        for kind, phrase in case["labels"]:
            starts = [m.start() for m in re.finditer(re.escape(phrase), text)]
            if len(starts) != expected[kind, phrase]:
                raise ValueError(f"Expected {expected[kind, phrase]} occurrences at {loc}: {phrase!r}")
            start = starts[used[kind, phrase]]
            used[kind, phrase] += 1
            gold.add((kind, start, start + len(phrase)))
        predicted = predictions[loc]
        for kind, start, end in gold & predicted:
            counts[kind]["TP"] += 1
        for kind, start, end in predicted - gold:
            counts[kind]["FP"] += 1
            errors.append((loc, "FP", kind, text[start:end]))
        for kind, start, end in gold - predicted:
            counts[kind]["FN"] += 1
            errors.append((loc, "FN", kind, text[start:end]))
        # Binary character accuracy: PII versus non-PII, ignoring type.
        g = set(i for _, a, b in gold for i in range(a, b))
        p = set(i for _, a, b in predicted for i in range(a, b))
        total_characters += len(text)
        correct_characters += len(text) - len(g ^ p)
    print(f"Evaluated {len(cases)} labelled document paragraphs")
    print("TYPE,TP,FP,FN,PRECISION,RECALL,F1")
    total = Counter()
    for kind in sorted(counts):
        c = counts[kind]
        total.update(c)
        precision = safe_ratio(c["TP"], c["TP"] + c["FP"])
        recall = safe_ratio(c["TP"], c["TP"] + c["FN"])
        f1 = safe_ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None
        print(f'{kind},{c["TP"]},{c["FP"]},{c["FN"]},{fmt(precision)},{fmt(recall)},{fmt(f1)}')
    p = safe_ratio(total["TP"], total["TP"] + total["FP"])
    r = safe_ratio(total["TP"], total["TP"] + total["FN"])
    f1 = safe_ratio(2 * p * r, p + r) if p is not None and r is not None else None
    print(f'OVERALL,{total["TP"]},{total["FP"]},{total["FN"]},{fmt(p)},{fmt(r)},{fmt(f1)}')
    print(f"CHARACTER_ACCURACY,{correct_characters}/{total_characters},{correct_characters / total_characters:.3f}")
    print("\nExact-span mismatches:")
    for loc, category, kind, value in errors:
        print(f"{loc} {category} {kind}: {value}")

if __name__ == "__main__":
    main()
