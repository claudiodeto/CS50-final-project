from app import app
import datetime
from models import db, Admin
from werkzeug.security import generate_password_hash

# create an admin user with username 'admin' and a secure password
admin = Admin(
    username="admin",
    password_hash=generate_password_hash("Eileen2025@NZ", method='pbkdf2:sha256', salt_length=8)
)
# update the database with the new admin user
with app.app_context():
    db.session.add(admin)
    db.session.commit()
    print("Admin user created!")