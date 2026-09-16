import time
import requests

url = "http://127.0.0.1:5000/login"
username = "user" 
passwords = ["111111", "abc123", "password", "123456", "123"]

for pwd in passwords:
    r = requests.post(url, data={"username": username, "password": pwd}, timeout=5)
    print(pwd, r.status_code, r.text[:80])
    time.sleep(2)