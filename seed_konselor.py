from app import app, db, User  # impor model & app kamu

USERS = [
    {"username": "KNS-0001", "password": "Konselor01ya!"},  # ≥12 karakter
    {"username": "KNS-0002", "password": "Konselor02ya!"},
]

def upsert_konselor(username: str, password: str):
    """Buat atau update akun konselor (jika sudah ada, password diganti)."""
    u = User.query.filter(
        (User.username == username) | 
        (User.username == username.upper()) | 
        (User.username == username.lower())
    ).first()

    if u:
        u.role = "konselor"
        u.set_password(password)
        db.session.commit()
        print(f"[UPDATE] {u.username} (role={u.role}) → password direset.")
    else:
        u = User(username=username.upper(), role="konselor")
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        print(f"[CREATE] {u.username} (role={u.role}) dibuat.")

if __name__ == "__main__":
    with app.app_context():
        for item in USERS:
            upsert_konselor(item["username"], item["password"])
        print("\nSelesai. Anda bisa login memakai kredensial berikut:")
        for item in USERS:
            print(f"  - {item['username']}  /  {item['password']}")
        print("\n**Keamanan:** ganti password setelah login pertama.")