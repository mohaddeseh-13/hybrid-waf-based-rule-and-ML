"""
Evaluation Metrics for Hybrid WAF
Precision, Recall, F1-score, False Positive Rate
"""

from collections import Counter


def calculate_metrics(results):
    """
    results: list of dict
    each item:
    {
        "true_label": 0 or 1,   # 1 = attack, 0 = benign
        "predicted": 0 or 1
    }
    """

    TP = FP = TN = FN = 0

    for r in results:
        if r["true_label"] == 1 and r["predicted"] == 1:
            TP += 1
        elif r["true_label"] == 0 and r["predicted"] == 1:
            FP += 1
        elif r["true_label"] == 0 and r["predicted"] == 0:
            TN += 1
        elif r["true_label"] == 1 and r["predicted"] == 0:
            FN += 1

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) else 0
    )
    false_positive_rate = FP / (FP + TN) if (FP + TN) else 0

    return {
        "TP": TP,
        "FP": FP,
        "TN": TN,
        "FN": FN,
        "Precision": round(precision, 3),
        "Recall": round(recall, 3),
        "F1-Score": round(f1_score, 3),
        "False Positive Rate": round(false_positive_rate, 3),
    }
