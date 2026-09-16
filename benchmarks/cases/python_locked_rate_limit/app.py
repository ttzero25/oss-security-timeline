import threading


login_attempts = {}
attempts_lock = threading.Lock()


@app.post("/login/<user_id>")
def login(user_id):
    with attempts_lock:
        if login_attempts.get(user_id, 0) < 5:
            authenticate(user_id)
            login_attempts[user_id] = login_attempts.get(user_id, 0) + 1
    return {"attempts": login_attempts.get(user_id, 0)}
