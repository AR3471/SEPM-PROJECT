"""
Utility: clear all vulnerability findings and activity logs from the SQLite DB.
Run:  python clear_db.py
"""
import sqlite3

DB_PATH = r"xss_users.db"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Show what's in there
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall()]
print("Tables found:", tables)

for t in tables:
    cur.execute(f'SELECT COUNT(*) FROM "{t}"')
    print(f"  {t}: {cur.fetchone()[0]} rows")

print()

# Clear findings and activity
if "findings" in tables:
    cur.execute("DELETE FROM findings")
    print(f"Cleared 'findings' table.")

if "activity" in tables:
    cur.execute("DELETE FROM activity")
    print(f"Cleared 'activity' table.")

conn.commit()

print()
print("Verifying after clear:")
for t in tables:
    cur.execute(f'SELECT COUNT(*) FROM "{t}"')
    print(f"  {t}: {cur.fetchone()[0]} rows")

conn.close()
print()
print("Done! Restart the server to apply changes.")
