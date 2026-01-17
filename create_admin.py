from getpass import getpass
import sys
from werkzeug.security import generate_password_hash
from app import app
from models import db, Admin

def main():
    with app.app_context():
        uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        print("About to modify DB:", uri)
        confirm = input("Type YES to continue and add an admin to this DB: ")
        if confirm != "YES":
            print("Aborted.")
            sys.exit(1)

        username = input("Admin username (default 'admin'): ") or "admin"
        pwd = getpass("Admin password (will be hidden): ")
        if not pwd:
            print("Password required.")
            sys.exit(1)

        admin = Admin(
            username=username,
            password_hash=generate_password_hash(pwd, method="pbkdf2:sha256")
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin created with id:", admin.id)

if __name__ == "__main__":
    main()