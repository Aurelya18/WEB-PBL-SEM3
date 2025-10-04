from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Buat semua tabel sesuai models
    db.create_all()

    # Cek apakah admin sudah ada
    if not User.query.filter_by(username="admin").first():
        hashed_password = generate_password_hash("1234", method="pbkdf2:sha256")
        admin = User(username="admin", password=hashed_password, role="admin")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user berhasil dibuat: username=admin, password=1234")
    else:
        print("⚠️ Admin user sudah ada, tidak ditambahkan lagi.")
