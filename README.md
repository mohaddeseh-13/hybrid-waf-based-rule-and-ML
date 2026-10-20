# اجرا بدون  docker:
pip install -r requirements.txt

# دو تا PowerShell:
پنجره اول — Backend:

cd C:\مسیر پوشه waf
python -m app.backend

پنجره دوم — WAF:

cd C:\مسیر پوشه waf
python -m app.main
#  اجرای داشبورد در مرورگر
http://localhost:5000/waf-dashboard


# اجرا با docker  در readme-Docker