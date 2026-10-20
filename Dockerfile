FROM python:3.11-slim

WORKDIR /app

# نصب وابستگی‌ها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کل پروژه
COPY . .

# آموزش مدل‌های ML هنگام build
RUN python -m ml.train

# پورت WAF
EXPOSE 5000

# اجرای WAF
CMD ["python", "-m", "app.main"]
