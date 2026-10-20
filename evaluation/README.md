# ارزیابی آماری WAF

این پوشه شامل ابزار محاسبه Precision/Recall/F1-Score روی یک مجموعه تست مستقل است.

## فایل‌ها

- `test_dataset.csv` — مجموعه تست مستقل (۱۱۹ نمونه: ۵۲ معمولی، ۳۸ SQL Injection، ۲۹ XSS)،
  جدا از دیتاست آموزشی مدل. ستون‌ها: `payload`, `label` (0=معمولی, 1=حمله), `type`.
- `metrics.py` — تابع `calculate_metrics()` که از روی فهرستی از `{true_label, predicted}`
  چهار معیار TP/FP/TN/FN و Precision/Recall/F1-Score/False Positive Rate را حساب می‌کند.
- `run_evaluation.py` — اسکریپت اجراکننده: هر ردیف `test_dataset.csv` را از طریق
  `HybridEngine.inspect()` واقعی رد می‌کند، نتیجه (BLOCK/ALLOW) را با برچسب واقعی مقایسه
  می‌کند، و معیارها را هم به‌صورت کلی و هم به تفکیک نوع payload چاپ می‌کند.

## نحوه اجرا

از پوشه اصلی پروژه (کنار `core/` و `app/`):

```
python evaluation/run_evaluation.py
```

## نکته درباره ویرایش test_dataset.csv

اگر payload جدیدی اضافه می‌کنید که خودش شامل کاما (`,`) است (مثلاً کوئری‌های SQL با
چند ستون مثل `SELECT username, password FROM users`)، کل فیلد payload را داخل
گیومه بگذارید تا CSV درست parse شود:

```
"' UNION SELECT username, password FROM users --",1,sql
```

در غیر این صورت کاما داخل payload به‌عنوان مرز ستون CSV در نظر گرفته می‌شود و آن
ردیف به‌درستی خوانده نخواهد شد.
