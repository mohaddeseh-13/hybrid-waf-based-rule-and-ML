import json
from collections import Counter
from flask import Blueprint, jsonify
import os

dashboard_api = Blueprint("dashboard_api", __name__)

LOG_FILE = "/app/waf.log"


def read_logs():
    logs = []

    if not os.path.isfile(LOG_FILE):
        return logs

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f.readlines()[-100:]:
                line = line.strip()

                if not line:
                    continue

                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return []

    return logs


# دریافت لاگ‌ها
@dashboard_api.route("/api/logs")
def get_logs():
    return jsonify(read_logs())


# آمار حملات
@dashboard_api.route("/api/stats")
def get_stats():
    logs = read_logs()

    attack_types = Counter()
    detection_methods = Counter()

    for log in logs:
        attack_type = log.get("attack_type")
        detection_method = log.get("detection_method")

        if attack_type:
            attack_types[attack_type] += 1

        if detection_method:
            detection_methods[detection_method] += 1

    return jsonify({
        "attack_types": dict(attack_types),
        "detection_methods": dict(detection_methods)
    })


# خلاصه مدیریتی
@dashboard_api.route("/api/summary")
def get_summary():
    logs = read_logs()

    total = len(logs)
    rule = 0
    ml = 0

    for log in logs:
        method = log.get("detection_method")

        if method == "Rule-Based":
            rule += 1
        elif method == "ML-Based":
            ml += 1

    return jsonify({
        "total_attacks": total,
        "rule_based": rule,
        "ml_based": ml
    })