from rules.owasp_other_advanced import (
    LDAPInjectionDetector,
    OpenRedirectDetector,
    PathTraversalDetector,
    CommandInjectionDetector,
    XXEDetector,
    SSRFDetector
)

_detectors = [
    LDAPInjectionDetector(),
    OpenRedirectDetector(),
    PathTraversalDetector(),
    CommandInjectionDetector(),
    XXEDetector(),
    SSRFDetector()
]

def detect_other(payload: str):
    results = []

    for detector in _detectors:
        res = detector.detect(payload)
        if res.get("is_attack"):
            results.append(res)

    if results:
        best = max(results, key=lambda x: x["confidence"])
        return True, best["confidence"], best["attack_type"]

    return False, 0.0, "None"
