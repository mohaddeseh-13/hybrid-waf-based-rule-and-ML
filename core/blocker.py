def block(reason: str):
    return {
        "action": "BLOCK",
        "reason": reason
    }


def allow():
    return {
        "action": "ALLOW"
    }
