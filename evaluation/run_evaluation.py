"""
اجرای ارزیابی آماری WAF روی مجموعه تست مستقل (evaluation/test_dataset.csv)

نحوه اجرا (از پوشه اصلی پروژه، کنار core/ و app/):
    python evaluation/run_evaluation.py

خروجی: تعداد TP/FP/TN/FN و معیارهای Precision/Recall/F1-Score/FPR،
هم به‌صورت کلی و هم به تفکیک نوع (sql/xss/benign)، روی صفحه چاپ می‌شود.
"""
import sys, csv
sys.path.insert(0, ".")
from core.engine import HybridEngine
from evaluation.metrics import calculate_metrics

DATASET_PATH = "evaluation/test_dataset.csv"

def load_dataset(path):
    valid_rows = []
    skipped = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=2):  # start=2: line 1 is header
            label = row.get("label", "")
            if label not in ("0", "1") or row.get(None) is not None:
                skipped.append((i, row))
                continue
            valid_rows.append(row)
    return valid_rows, skipped

def main():
    engine = HybridEngine()
    rows, skipped = load_dataset(DATASET_PATH)

    if skipped:
        print(f"[هشدار] {len(skipped)} ردیف به دلیل کاما بدون Escape در payload، به‌درستی parse نشدند و کنار گذاشته شدند:")
        for line_no, row in skipped:
            print(f"    خط {line_no}: {row}")
        print()

    results = []
    by_type = {}
    for row in rows:
        payload = row["payload"]
        true_label = int(row["label"])
        ptype = row.get("type", "unknown")

        verdict = engine.inspect(payload, source_ip="127.0.0.1")
        predicted = 1 if verdict["action"] == "BLOCK" else 0

        entry = {"true_label": true_label, "predicted": predicted}
        results.append(entry)
        by_type.setdefault(ptype, []).append(entry)

    overall = calculate_metrics(results)
    print("=" * 55)
    print(f"نتیجه کلی روی {len(results)} نمونه معتبر (از {len(rows) + len(skipped)} نمونه اصلی)")
    print("=" * 55)
    for k, v in overall.items():
        print(f"  {k}: {v}")

    print()
    print("=" * 55)
    print("تفکیک بر اساس نوع payload")
    print("=" * 55)
    for ptype, entries in by_type.items():
        m = calculate_metrics(entries)
        print(f"  [{ptype}]  n={len(entries)}  TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']}  "
              f"Precision={m['Precision']} Recall={m['Recall']} F1={m['F1-Score']}")

if __name__ == "__main__":
    main()
