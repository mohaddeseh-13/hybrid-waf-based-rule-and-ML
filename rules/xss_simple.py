from rules.xss_advanced import XSSDetector

_detector = XSSDetector()

def detect_xss(payload: str):
    result = _detector.detect(payload)
    return result["is_attack"], result["confidence"]
