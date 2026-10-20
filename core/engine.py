from rules.sql_simple import detect_sql
from rules.xss_simple import detect_xss
from rules.owasp_other import detect_other

from ml.sql_model import ml_detect_sql
from ml.xss_model import ml_detect_xss

from core.blocker import block, allow
from core.logger import log_event


ML_THRESHOLD = 0.7


class HybridEngine:
    """
    Hybrid WAF Decision Engine
    Rule-Based + Machine Learning
    """

    def inspect(self, payload: str, source_ip: str = "unknown"):
        #  Rule-Based : SQL 
        sql_attack, sql_conf = detect_sql(payload)
        if sql_attack:
            log_event("SQL Injection", source_ip, "Rule-Based", sql_conf)
            return block("SQL Injection (Rule-Based)")

        # Rule-Based : XSS
        xss_attack, xss_conf = detect_xss(payload)
        if xss_attack:
            log_event("XSS", source_ip, "Rule-Based", xss_conf)
            return block("XSS (Rule-Based)")

        #  Rule-Based : Other OWASP 
        other_attack, other_conf, other_type = detect_other(payload)
        if other_attack:
            log_event(other_type, source_ip, "Rule-Based", other_conf)
            return block(f"{other_type} (Rule-Based)")

        #  ML-Based : SQL
        ml_sql_attack, ml_sql_conf = ml_detect_sql(payload)
        if ml_sql_attack and ml_sql_conf >= ML_THRESHOLD:
            log_event("SQL Injection", source_ip, "ML-Based", ml_sql_conf)
            return block("SQL Injection (ML-Based)")

        #  ML-Based : XSS 
        ml_xss_attack, ml_xss_conf = ml_detect_xss(payload)
        if ml_xss_attack and ml_xss_conf >= ML_THRESHOLD:
            log_event("XSS", source_ip, "ML-Based", ml_xss_conf)
            return block("XSS (ML-Based)")

        # Allow 
        return allow()
