#!/usr/bin/env python3
"""Проверяет содержимое БД напрямую, минуя приложение."""
import sqlite3, sys

db = sqlite3.connect(sys.argv[1])
command = sys.argv[2]

if command == "hash":
    print(db.execute("SELECT password_hash FROM Users WHERE username=?", (sys.argv[3],)).fetchone()[0])
elif command == "ops":
    print(",".join(r[0] for r in db.execute("SELECT DISTINCT operation_type FROM Operations ORDER BY 1")))
elif command == "active":
    print(db.execute("SELECT COUNT(*) FROM Files WHERE location=? AND deleted_at IS NULL", (sys.argv[3],)).fetchone()[0])
elif command == "tamper":
    for sql in ("UPDATE AuditLog SET success=1", "DELETE FROM AuditLog", "DELETE FROM Operations"):
        try:
            db.execute(sql)
            print("TAMPERED")
        except sqlite3.DatabaseError:
            print("blocked")
