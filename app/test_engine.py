from core.engine import HybridEngine

engine = HybridEngine()

test_payloads = [
    # SQL Injection (Rule-Based)
    "1 OR 1=1",

    # SQL Injection (ML-Based)
    "SELECT username FROM users",

    # XSS (Rule-Based)
    "<script>alert(1)</script>",

    # XSS (ML-Based)
    "<svg onload=alert(1)>",

    # Other OWASP
    "../etc/passwd",

    # Benign
    "hello world"
]

for payload in test_payloads:
    result = engine.inspect(payload, source_ip="127.0.0.1")
    print("=" * 50)
    print(f"Payload: {payload}")
    print(f"Result: {result}")
