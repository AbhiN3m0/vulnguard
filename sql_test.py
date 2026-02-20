import sqlite3

conn = sqlite3.connect("test.db")
cursor = conn.cursor()

user_input = input()

# ❌ vulnerable
query = "SELECT * FROM users WHERE id=" + user_input
cursor.execute(query)

# ❌ vulnerable fstring
cursor.execute(f"SELECT * FROM users WHERE id={user_input}")

# ❌ vulnerable format
cursor.execute("SELECT * FROM users WHERE id={}".format(user_input))

# ✅ safe parameterized
cursor.execute("SELECT * FROM users WHERE id=?", (user_input,))

