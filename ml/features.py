import re
import math

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete",
    "drop", "or", "and", "--", ";", "'"
]

XSS_KEYWORDS = [
    "<script", "javascript:", "onerror", "onload", "<img", "<svg"
]

def entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_features(payload):
    payload = payload.lower()
    
    features = {}
    
    features["length"] = len(payload)
    features["entropy"] = entropy(payload) if payload else 0
    
    features["special_chars"] = sum(
        payload.count(c) for c in ["'", '"', "<", ">", ";", "(", ")"]
    )
    
    for kw in SQL_KEYWORDS:
        features[f"sql_{kw}"] = 1 if kw in payload else 0
    
    for kw in XSS_KEYWORDS:
        features[f"xss_{kw}"] = 1 if kw in payload else 0
    
    return features
