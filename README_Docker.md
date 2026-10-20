# راهنمای اجرا با Docker

```bash
docker-compose up --build
```

## اجرای با سایت واقعی

#در فایل docker-compose.yml :

```yaml
- WAF_BACKEND_URL=http://backend:5001
تغییر به :
- WAF_BACKEND_URL=https://your-real-website.com
```

سپس فقط سرویس waf را اجرا کنید:

```bash
docker-compose up --build waf
```


## دستورات مفید

```bash
# اجرا در پس‌زمینه
docker-compose up -d --build

# مشاهده لاگ‌های زنده
docker-compose logs -f waf

# توقف
docker-compose down

# مشاهده وضعیت
docker-compose ps
```
## اجرای داشبورد:
باز کردن درمرورگر
http://localhost:5000/waf-dashboard

## تست سریع بعد از اجرا

```bash
# تست SQL Injection (باید بلاک شود)
curl "http://localhost:5000/test?q=' OR 1=1 --"

# تست XSS (باید بلاک شود)
curl "http://localhost:5000/test?q=<script>alert(1)</script>"

# تست درخواست معمولی (باید رد شود)
curl "http://localhost:5000/"
```
