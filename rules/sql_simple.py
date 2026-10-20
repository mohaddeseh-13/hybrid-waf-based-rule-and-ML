from rules.sql_advanced import SQLInjectionDetector

_detector = SQLInjectionDetector()

def detect_sql(payload: str):
    result = _detector.detect(payload)
    return result["is_attack"], result["confidence"]
