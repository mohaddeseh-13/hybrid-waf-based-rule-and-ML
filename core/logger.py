import json
from datetime import datetime

LOG_FILE = "waf.log"


def log_event(attack_type, source_ip, method, confidence=None):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "attack_type": attack_type,
        "source_ip": source_ip,
        "detection_method": method,
        "confidence": confidence
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
