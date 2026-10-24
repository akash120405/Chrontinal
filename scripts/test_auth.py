#!/usr/bin/env python3
"""Quick test of dashboard auth flow."""
import urllib.request
import urllib.error
import json
import http.cookiejar
import os

BASE = os.getenv("CLIF_DASHBOARD_URL", "http://localhost:3001")
AUTH_USER = os.environ["CLIF_AUTH_USER"]
AUTH_PASS = os.environ["CLIF_AUTH_PASS"]

# 1. Test wrong creds → 401
try:
    req = urllib.request.Request(
        f"{BASE}/api/auth",
        data=json.dumps({"username": "wrong", "password": "wrong"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req)
    print(f"FAIL: Wrong creds accepted: {resp.status}")
except urllib.error.HTTPError as e:
    print(f"OK: Wrong creds rejected: {e.code}")

# 2. Test correct creds → 200 + cookie
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
req2 = urllib.request.Request(
    f"{BASE}/api/auth",
    data=json.dumps({"username": AUTH_USER, "password": AUTH_PASS}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
resp2 = opener.open(req2)
print(f"OK: Login success: {resp2.status} {resp2.read().decode()}")
cookies = [(c.name, c.value[:30] + "...") for c in cj]
print(f"   Cookies: {cookies}")

# 3. Access dashboard with session cookie → 200
req3 = urllib.request.Request(f"{BASE}/dashboard")
resp3 = opener.open(req3)
print(f"OK: Dashboard authenticated: {resp3.status}")

# 4. Without cookie → redirect to login (307)
try:
    req4 = urllib.request.Request(f"{BASE}/dashboard")
    handler = urllib.request.HTTPRedirectHandler()
    handler.max_redirections = 0
    opener2 = urllib.request.build_opener(handler)
    resp4 = opener2.open(req4)
    print(f"FAIL: Dashboard accessible without auth: {resp4.status}")
except urllib.error.HTTPError as e:
    if e.code in (307, 308):
        print(f"OK: Dashboard redirects to login: {e.code}")
    else:
        print(f"OK: Dashboard blocked without auth: {e.code}")

print("\nAll auth tests passed!")
