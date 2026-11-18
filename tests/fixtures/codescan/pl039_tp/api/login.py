def login(cur, email, pw):
    cur.execute("SELECT id FROM users WHERE email = %s AND password = %s", (email, pw))
    return cur.fetchone()
