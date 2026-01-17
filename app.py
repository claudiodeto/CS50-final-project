import datetime
import os
from datetime import timedelta
from helpers import admin_or_surgeon_required, admin_required, admin_secretary_or_surgeon_required, any_user_required, secretary_or_surgeon_required, secretary_required, surgeon_required, patient_required
from flask import Flask, flash, logging, render_template, redirect, request, session, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from models import Admin, Secretary, AuditLog, db, Surgeon, Patient, Appointment, Admission, Diagnosis, Surgery, Complication, PasswordResetToken
from sqlalchemy.exc import SQLAlchemyError
import re
import secrets
import sqlite3


from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "Eileen2025Andnow?" 

# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False  # Standard: session ends with browser
app.config["SESSION_TYPE"] = "filesystem"
Session(app)  # Initialize server-side session

# ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

# configure SQLAlchemy: build a correct absolute filesystem URI for the default DB
default_path = os.path.join(os.path.dirname(__file__), "static", "surgery.db")
default_db = f"sqlite:///{os.path.abspath(default_path)}"   # yields sqlite:////full/path/to/static/surgery.db
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", default_db)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)  # Initialize db with your app
migrate = Migrate(app, db)  # Initialize Flask-Migrate

# configure SQLite connection (use absolute path too)
def get_db_connection():
    db_path = os.environ.get("DATABASE_URL_PATH") or os.path.abspath(default_path)
    # if DATABASE_URL_PATH not set, use default_path; ensure we pass the filesystem path to sqlite3.connect
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# configure response headers to prevent caching
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



# --- Index & Utility ---
@app.route("/")
def index():
    return render_template("index.html")



# --- Authentication (Login/Logout/Set Password) ---


# admin login route
@app.route("/admin_login", methods=["GET", "POST"])

def admin_login():
    # Forget any user id
    session.clear() 

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # check if username and password are provided
        if not username or not password:
            return "Must provide username and password", 403
        
        # Authenticate admin user
        admin = Admin.query.filter_by(username=username).first()

        # Check if admin exists and password is correct
        if admin == None or not check_password_hash(admin.password_hash, password):
            flash("Invalid credentials", "danger")
            return render_template("admin_login.html")
        
        else:
            session["is_admin"] = True

            # Log the admin in
            session["admin_id"] = admin.id

            # Log the login action
            log = AuditLog(
                user_id=admin.id,
                action="login",
                table_name="Admin",
                record_id=admin.id,
                timestamp=datetime.datetime.now(),
                details="Admin logged in"
            )
            db.session.add(log)
            db.session.commit()

            return redirect("/admin_dashboard")
   

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("admin_login.html")


# Patient login route
@app.route("/patients_login", methods=["GET", "POST"])

def patients_login():
    # Forget any user id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # check if username and password are provided
        if not username or not password:
            return "Must provide username and password", 403

        # Authenticate user
        user = Patient.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user == None or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials", "danger")
            return render_template("patients_login.html")

        # Log the user in
        session["patient_id"] = user.id

        # Check if user needs to set a password
        if user.needs_password:
            session["pending_user_id"] = user.id
            session["pending_user_type"] = "patient"
            return redirect("/set_password")

        # Log the login action
        log = AuditLog(
            user_id=user.id,
            action="login",
            table_name="Patient",
            record_id=user.id,
            timestamp=datetime.datetime.now(),
            details="User logged in"
        )
        db.session.add(log)
        db.session.commit()

        return redirect("/patients_records/{}".format(user.id))
    
    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("patients_login.html")


# Secretary login route
@app.route("/secretary_login", methods=["GET", "POST"])

def secretary_login():
    # Forget any user id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if username and password are provided
        if not username or not password:
            flash("Must provide username and password", "danger")
            return render_template("secretary_login.html")

        # Authenticate user
        user = Secretary.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user == None or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials", "danger")
            return render_template("secretary_login.html")

        # Log the user in
        session["secretary_id"] = user.id

        # Check if user needs to set a password
        if user.needs_password:
            session["pending_user_id"] = user.id
            session["pending_user_type"] = "secretary"
            return redirect("/set_password")

        # Log the login action
        log = AuditLog(
            user_id=user.id,
            action="login",
            table_name="Secretary",
            record_id=user.id,
            timestamp=datetime.datetime.now(),
            details="User logged in"
        )
        db.session.add(log)
        db.session.commit()

        return redirect("/secretaries_dashboard")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("secretary_login.html")


# Surgeon login route
@app.route("/surgeons_login", methods=["GET", "POST"])

def surgeons_login():
    # Forget any user id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if username and password are provided
        if not username or not password:
            flash("Must provide username and password", "danger")
            return render_template("surgeons_login.html")

        # Authenticate user
        user = Surgeon.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user == None or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials", "danger")
            return render_template("surgeons_login.html")

        # Log the user in
        session["surgeon_id"] = user.id

        # Check if user needs to set a password
        if user.needs_password:
            session["pending_user_id"] = user.id
            session["pending_user_type"] = "surgeon"
            return redirect("/set_password")

        # Log the login action
        log = AuditLog(
            user_id=user.id,
            action="login",
            table_name="Surgeon",
            record_id=user.id,
            timestamp=datetime.datetime.utcnow(),
            details="User logged in"
        )
        db.session.add(log)
        db.session.commit()

        return redirect("/surgeons_dashboard")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("surgeons_login.html")


# route to set password for users who need to set a password (surgeon, patient or secretary)
@app.route("/set_password", methods=["GET", "POST"])
def set_password():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Check if password and confirmation are provided
        if not password or not confirm_password:
            return "Must provide password and confirmation", 403

        # Check if passwords match
        if password != confirm_password:
            return "Passwords do not match", 403
        
        # Retrieve user based on pending_user_id and pending_user_type in session
        user_id = session.get("pending_user_id")
        user_type = session.get("pending_user_type")

        if user_type == "surgeon":
            user = db.session.get(Surgeon, user_id)
            redirect_url = "/surgeons_dashboard"
        elif user_type == "patient":
            user = db.session.get(Patient, user_id)
            redirect_url = "/patients_records/{}".format(user_id)
        elif user_type == "secretary":
            user = db.session.get(Secretary, user_id)
            redirect_url = "/secretaries_dashboard"
        else:
            return redirect("/")
        
        if not user:
            return "User not found", 404
        
        # Update user's password
        user.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        user.needs_password = False

        # Log the password set action
        log = AuditLog(
            user_id=user.id,
            action="set_password",
            table_name=user_type.capitalize(),
            record_id=user.id,
            timestamp=datetime.datetime.now(),
        )
        db.session.add(log)
        db.session.commit()

        # Clear pending user info from session
        session.pop("pending_user_id", None)
        session.pop("pending_user_type", None)
        return redirect(redirect_url)

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("set_password.html")


# route to log out
@app.route("/logout")
def logout():
    # Determine user type and ID before clearing session
    if session.get("admin_id"):
        user_id = session.get("admin_id")
        table_name = "Admin"
        details = "Admin logged out"
        record_id = user_id
    elif session.get("surgeon_id"):
        user_id = session.get("surgeon_id")
        table_name = "Surgeon"
        details = "Surgeon logged out"
        record_id = user_id
    elif session.get("secretary_id"):
        user_id = session.get("secretary_id")
        table_name = "Secretary"
        details = "Secretary logged out"
        record_id = user_id
    elif session.get("patient_id"):
        user_id = session.get("patient_id")
        table_name = "Patient"
        details = "Patient logged out"
        record_id = user_id
    else:
        user_id = None
        table_name = "Unknown"
        details = "Unknown user logged out"
        record_id = None

    # Log the logout action
    log = AuditLog(
        user_id=user_id,
        action="logout",
        table_name=table_name,
        record_id=record_id,
        timestamp=datetime.datetime.now(),
        details=details
    )
    db.session.add(log)
    db.session.commit()

    # Forget any user id
    session.clear()

    flash("You have been logged out.")

    # Redirect user to login form
    return redirect("/")


# Forgot Password route
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    # Get user_type from URL query parameter
    user_type = request.args.get("user_type") if request.method == "GET" else request.form.get("user_type")

    if request.method == "POST":
        username = request.form.get("username")

        if not username or not user_type:
            flash("Please provide username.")
            return redirect(f"/forgot_password?user_type={user_type if user_type else ''}")

        # Retrieve user based on username and user_type
        if user_type == "surgeon":
            user = Surgeon.query.filter_by(username=username).first()
        elif user_type == "patient":
            user = Patient.query.filter_by(username=username).first()
        elif user_type == "secretary":
            user = Secretary.query.filter_by(username=username).first()
        else:
            flash("Invalid user type.")
            return redirect(f"/forgot_password?user_type={user_type if user_type else ''}")

        if not user:
            flash("User not found.")
            return redirect(f"/forgot_password?user_type={user_type if user_type else ''}")
        
        # Generate a secure token
        token = secrets.token_urlsafe(32)
        expires = datetime.datetime.now() + timedelta(hours=1)

        # Store the token in the database
        reset_token = PasswordResetToken(
            token=token,
            user_type=user_type,
            user_id=user.id,
            expires=expires,
            created_at=datetime.datetime.now()
        )
        db.session.add(reset_token)
        db.session.commit()

        # create a reset link (in a real app, this would be emailed to the user)
        reset_link = f"http://127.0.0.1:5000/reset_password/{token}"
        session["reset_link"] = reset_link
        return redirect("/reset_link_sent")

    return render_template("forgot_password.html", user_type=user_type)

#  Reset Link Sent route
@app.route("/reset_link_sent")
def reset_link_sent():
    reset_link = session.pop("reset_link", None)
    if not reset_link:
        return redirect("/")
    return render_template("reset_link_sent.html", reset_link=reset_link)

# Reset Password with Token route   
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()

    if not reset_token:
        flash("Invalid or expired token.")
        return redirect("/forgot_password")
    
    if reset_token.expires < datetime.datetime.now():
        flash("Token has expired.")
        db.session.delete(reset_token)
        db.session.commit()
        return redirect("/forgot_password")

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or not confirm_password:
            flash("Please provide both password fields.")
            return redirect(f"/reset_password/{token}")

        if new_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(f"/reset_password/{token}")

        # Retrieve user based on user_type and user_id from the token
        if reset_token.user_type == "surgeon":
            user = Surgeon.query.get(reset_token.user_id)
        elif reset_token.user_type == "patient":
            user = Patient.query.get(reset_token.user_id)
        elif reset_token.user_type == "secretary":
            user = Secretary.query.get(reset_token.user_id)
        else:
            flash("Invalid user type.")
            return redirect("/forgot_password")

        if not user:
            flash("User not found.")
            return redirect("/forgot_password")

        # Update user's password
        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)

        # Log the password reset action
        log = AuditLog(
            user_id=user.id,
            action="reset_password",
            table_name=type(user).__name__,
            record_id=user.id,
            timestamp=datetime.datetime.now(),
            details="Password reset via token"
        )
        db.session.add(log)
        
        # Delete the used token
        db.session.delete(reset_token)
        db.session.commit()

        flash("Password has been reset successfully!")
        return redirect("/")

    return render_template("reset_password.html", token=token)


# change password route for logged-in users
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_new_password = request.form.get("confirm_new_password")

        # Check if all fields are provided
        if not current_password or not new_password or not confirm_new_password:
            return "All fields are required", 403

        # Check if new passwords match
        if new_password != confirm_new_password:
            return "New passwords do not match", 403

        # Determine user type and retrieve user
        if session.get("admin_id"):
            user = db.session.get(Admin, session["admin_id"])
        elif session.get("surgeon_id"):
            user = db.session.get(Surgeon, session["surgeon_id"])
        elif session.get("secretary_id"):
            user = db.session.get(Secretary, session["secretary_id"])
        elif session.get("patient_id"):
            user = db.session.get(Patient, session["patient_id"])
        else:
            flash("No user logged in.")
            return redirect("/")

        # Verify current password
        if not check_password_hash(user.password_hash, current_password):
            return "Current password is incorrect", 403

        # Update user's password
        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)

        # Log the password change action
        log = AuditLog(
            user_id=user.id,
            action="change_password",
            table_name=type(user).__name__,
            record_id=user.id,
            timestamp=datetime.datetime.now(),
        )
        db.session.add(log)
        db.session.commit()

        flash("Password changed successfully!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("change_password.html")


# --- Dashboards ---


# route to admin dashboard (admin only)
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html")


# route to secretary dashboard (secretary only)
@app.route("/secretaries_dashboard")
@secretary_required
def secretaries_dashboard():
    return render_template("secretaries_dashboard.html")


# route to surgeons dashboard (surgeon only)
@app.route("/surgeons_dashboard")
@surgeon_required
def surgeons_dashboard():
    return render_template("surgeons_dashboard.html")



# -- User Management Routes(Admin Only) ---


# route to add a new secretary (admin only)
@app.route("/add_secretary", methods=["GET", "POST"])
@admin_required
def add_secretary():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        gender = request.form.get("gender")
        date_of_birth = request.form.get("date_of_birth")
        contact_info = request.form.get("contact_info")

        if not username or not password or not confirm_password or not first_name or not last_name:
            return "Missing required fields", 400       
        if password != confirm_password:
            return "Passwords do not match", 400
        
        # Check if username already exists
        existing_secretary = Secretary.query.filter_by(username=username).first()
        if existing_secretary:
            return "Username already exists", 400
        
        # Hash the password for security
        try:
            password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        except Exception as e:
            return f"Error hashing password: {e}", 500
        
        # convert gender to single character
        if gender == "male":
            gender = "M"
        elif gender == "female":
            gender = "F"
        elif gender == "other":
            gender = "O"    
        
        # convert date_of_birth to a date object    
        try:
            date_of_birth = datetime.datetime.strptime(date_of_birth, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            date_of_birth = None 
        
        # update database with new secretary by updating class instance
        new_secretary = Secretary(
            username=username,
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            contact_info=contact_info
        )
        
        # log the addition of a new secretary
        log = AuditLog(
            user_id=session.get("admin_id"),
            action="add",
            table_name="Admin",
            record_id=new_secretary.id,
            timestamp=datetime.datetime.now(),
            details=f"Added new secretary: {first_name} {last_name} (ID: {username})"
        )
        db.session.add(log)
        db.session.add(new_secretary)
        db.session.commit()
        flash("New secretary added successfully!")
        return redirect("/allowed_users")
    
    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("add_secretary.html")


# route to delete a secretary (admin only)
@app.route("/delete_secretary/<int:secretary_id>", methods=["POST"])
@admin_required
def delete_secretary(secretary_id):
    secretary = Secretary.query.get(secretary_id)
    if not secretary:
        return "Secretary not found", 404
    
    # log the deletion of the secretary
    log = AuditLog(
        user_id=session.get("admin_id"),
        action="delete",
        table_name="Admin",
        record_id=secretary.id,
        timestamp=datetime.datetime.now(),
        details=f"Deleted secretary: {secretary.first_name} {secretary.last_name} (ID: {secretary.username})"
    )
    db.session.add(log)
    db.session.delete(secretary)
    db.session.commit()

    flash("Secretary deleted successfully!")
    return redirect("/allowed_users")


# route to add a new surgeon (admin only)
@app.route("/add_surgeon", methods=["GET", "POST"])
@admin_required

def add_surgeon():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        surgeon_code = request.form.get("surgeon_code")
        confirm_password = request.form.get("confirm_password")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        gender = request.form.get("gender")
        date_of_birth = request.form.get("date_of_birth")
        specialty = request.form.get("specialty")
        contact_info = request.form.get("contact_info")

        if not username or not password or not confirm_password or not first_name or not last_name:
            return "Missing required fields", 400
        if password != confirm_password:
            return "Passwords do not match", 400  
          
        # Check if username already exists
        existing_surgeon = Surgeon.query.filter_by(username=username).first()
        if existing_surgeon:
            return "Username already exists", 400
        
        # Hash the password for security
        try:
            password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        except Exception as e:
            return f"Error hashing password: {e}", 500

        # convert gender to single character
        if gender == "male":
            gender = "M"
        elif gender == "female":
            gender = "F"
        elif gender == "other":
            gender = "O"
        
        # convert date_of_birth to a date object
        try:
            print(f"Raw date_of_birth input: {date_of_birth}")  # Debugging line
            date_of_birth = datetime.datetime.strptime(date_of_birth, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        # update database with new surgeon by updating class instance
        new_surgeon = (Surgeon( 
            username=username,
            password_hash=password_hash,
            surgeon_code=surgeon_code,
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            specialty=specialty,
            contact_info=contact_info
        ))

        # log the addition of a new surgeon
        log = AuditLog(
            user_id=session.get("admin_id"),
            action="add",
            table_name="Admin",
            record_id=new_surgeon.id,
            timestamp=datetime.datetime.now(),
            details=f"Added new surgeon: {first_name} {last_name} (Code: {surgeon_code})"
        )
        db.session.add(log)
        db.session.add(new_surgeon)
        db.session.commit()

        flash("New surgeon added successfully!")

        return redirect("/allowed_users")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("add_surgeon.html")


# route to delete a surgeon (admin only)
@app.route("/delete_surgeon/<int:surgeon_id>", methods=["POST"])
@admin_required
def delete_surgeon(surgeon_id):
    surgeon = Surgeon.query.get(surgeon_id)
    if not surgeon:
        return "Surgeon not found", 404
    
    try:
        # remove dependent records first (appointments, surgeries, admissions, diagnoses)
        Appointment.query.filter_by(surgeon_id=surgeon.id).delete()
        Surgery.query.filter_by(surgeon_id=surgeon.id).delete()
        Admission.query.filter_by(surgeon_id=surgeon.id).delete()
        Diagnosis.query.filter_by(surgeon_id=surgeon.id).delete()
        
        # ensure deletes applied before deleting surgeon
        db.session.flush()

        # log the deletion of the surgeon
        log = AuditLog(
            user_id=session.get("admin_id"),
            action="delete",
            table_name="Admin",
            record_id=surgeon.id,
            timestamp=datetime.datetime.now(),
            details=f"Deleted surgeon: {surgeon.first_name} {surgeon.last_name} (Code: {surgeon.surgeon_code})"
        )
        db.session.add(log)
        db.session.delete(surgeon)
        db.session.commit()

        flash("Surgeon deleted successfully!")
        return redirect("/allowed_users")
    
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Error deleting surgeon and dependent records")
        flash("An error occurred due to database constraints. Surgeon could not be deleted.", "danger")
        return redirect("/allowed_users")


# route to view surgeons list (admin only)
@app.route("/surgeons_list")
@admin_required
def surgeons_list():
    surgeons = Surgeon.query.all()
    return render_template("surgeons_list.html", surgeons=surgeons)


# route to view secretaries list (admin only)
@app.route("/secretaries_list")
@admin_required
def secretaries_list():
    secretaries = Secretary.query.all()
    return render_template("secretaries_list.html", secretaries=secretaries)


# route to view allowed users (admin only)
@app.route("/allowed_users")
@admin_required
def allowed_users():
    admins = Admin.query.all()
    surgeons = Surgeon.query.all()
    secretaries = Secretary.query.all()
    # return only patients who have user accounts
    patients = Patient.query.filter(Patient.username.isnot(None)).all()
    return render_template("allowed_users.html", admins=admins, surgeons=surgeons, secretaries=secretaries ,patients=patients)


# --- Patient Records Management Routes ---


# route to enter new patients records (admin only)
@app.route("/enter_new_patient_records", methods=["GET", "POST"])
@admin_required
def enter_new_patient_records():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        NHI = request.form.get("patient_NHI")
        first_name = request.form.get("patient_first_name")
        last_name = request.form.get("patient_last_name")
        gender = request.form.get("gender")
        date_of_birth = request.form.get("date_of_birth")
        contact_info = request.form.get("contact_info")
        emergency_contact_name = request.form.get("emergency_contact_name")
        emergency_contact_phone = request.form.get("emergency_contact_phone")
        medical_history = request.form.get("medical_history")
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate required fields
        if not NHI or not first_name or not last_name or not gender or not date_of_birth or not contact_info:
            return "Missing required fields", 400
        
        # validate NHI format (assuming NHI is 6 characters long)
        if re.search(r"^[A-Z]{3}\d{3}$", NHI):
            NHI = NHI.upper()  # Ensure NHI is uppercase    
        else:
            raise ValueError("invalid NHI")
        
        # Check if patient with the same NHI already exists
        existing_patient = Patient.query.filter_by(NHI=NHI).first()
        if existing_patient:
            return render_template("patients_records.html", patient=existing_patient)

        # convert gender to single character
        if gender == "male":
            gender = "M"
        elif gender == "female":
            gender = "F"
        elif gender == "other":
            gender = "O"

        # convert date_of_birth to a date object
        try:
            date_of_birth = datetime.datetime.strptime(date_of_birth, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        # Hash the password for security
        if password:
            try:
                password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            except Exception as e:
                return f"Error hashing password: {e}", 500
        
        # update database with new patient by updating class instance
        new_patient = Patient(
            NHI=NHI,
            first_name=first_name,
            last_name=last_name, 
            gender=gender,
            date_of_birth=date_of_birth,
            contact_info=contact_info,
            emergency_contact_name=emergency_contact_name,
            emergency_contact_phone=emergency_contact_phone,
            medical_history=medical_history,
            username=username,
            password_hash=password
        )

        db.session.add(new_patient)


        # log the addition of a new patient
        log = AuditLog(
            user_id=session.get("admin_id"),
            action="add",
            table_name="Admin",
            record_id=new_patient.id,
            timestamp=datetime.datetime.now(),
            details=f"Added new patient: {first_name} {last_name} (NHI: {NHI})"
        )
        db.session.add(log)
        db.session.commit()

        flash("New patient records added successfully!")
        return redirect("/allowed_users")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("enter_new_patient_records.html")


# route to edit an existing patient's records (admin only; surgeon can only modify medical history)
@app.route("/edit_patient/<int:patient_id>", methods=["GET", "POST"])
@admin_or_surgeon_required
def edit_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # If surgeon, only allow editing medical_history (and password)
        if session.get("surgeon_id"):
            patient.medical_history = request.form.get("medical_history")

        # If admin, allow editing all fields
        elif session.get("admin_id"):
            patient.NHI = request.form.get("patient_NHI")
            patient.first_name = request.form.get("patient_first_name")
            patient.last_name = request.form.get("patient_last_name")
            patient.gender = request.form.get("gender")
            date_of_birth = request.form.get("date_of_birth")
            if date_of_birth:
                try:
                    patient.date_of_birth = datetime.datetime.strptime(date_of_birth, "%Y-%m-%d").date()
                except ValueError:
                    return "Invalid date format. Use YYYY-MM-DD.", 400
            patient.contact_info = request.form.get("contact_info")
            patient.emergency_contact_name = request.form.get("emergency_contact_name")
            patient.emergency_contact_phone = request.form.get("emergency_contact_phone")
            patient.medical_history = request.form.get("medical_history")
            patient.username = request.form.get("username")
            new_password = request.form.get("new_password")
            if new_password:
                patient.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
                patient.needs_password = True

        # Log the edit action
        log = AuditLog(
            user_id=session.get("admin_id") or session.get("surgeon_id"),
            action="edit",
            table_name="Admin" if session.get("admin_id") else "Surgeon",
            record_id=patient.id,
            timestamp=datetime.datetime.now(),
            details=f"Edited patient: {patient.first_name} {patient.last_name} (NHI: {patient.NHI})"
        )
        db.session.add(log)
        db.session.commit()
        flash("Patient records updated successfully!")
        return redirect(f"/patients_records/{patient.id}")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("edit_patient.html", patient_id=patient.id, patient=patient)

# route to delete a patient's records (admin only)
@app.route("/delete_patient/<int:patient_id>", methods=["POST"])
@admin_required
def delete_patient(patient_id):
    patient = Patient.query.get(patient_id)
    if not patient:
        return "Patient not found", 404
    
    try:
        # remove dependent records first (appointments, surgeries, admissions, diagnoses)
        Appointment.query.filter_by(patient_id=patient.id).delete()
        Surgery.query.filter_by(patient_id=patient.id).delete()
        Admission.query.filter_by(patient_id=patient.id).delete()
        Diagnosis.query.filter_by(patient_id=patient.id).delete()
        
        # ensure deletes applied before deleting patient
        db.session.flush()

        # log the deletion of the patient
        log = AuditLog(
            user_id=session.get("admin_id"),
            action="delete",
            table_name="Admin",
            record_id=patient.id,
            timestamp=datetime.datetime.now(),
            details=f"Deleted patient: {patient.first_name} {patient.last_name} (NHI: {patient.NHI})"
        )
        db.session.add(log)
        db.session.delete(patient)
        db.session.commit()

        flash("Patient deleted successfully!")
        return redirect("/allowed_users")
    
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Error deleting patient and dependent records")
        flash("An error occurred due to database constraints. Patient could not be deleted.", "danger")
        return redirect(f"/patients_records/{patient.id}")
    

# route to search patients records (sadmin, secretary or surgeon only)
@app.route("/search_patients_records", methods=["GET", "POST"])
@admin_secretary_or_surgeon_required

def search_patients_records():

    # initialize empty list for patients search results
    patients = []

    # search for patients by NHI, first name, last name or date of birth
    if request.method == "POST":
        nhi_query = request.form.get("NHI")
        first_name_query = request.form.get("first_name")
        last_name_query = request.form.get("last_name")
        dob_query = request.form.get("date_of_birth")

        # address lack of input
        if not (nhi_query or first_name_query or last_name_query or dob_query):
            return "Please provide at least one search criteria.", 400
        
        # check for correct date format
        if dob_query:
            try:
                datetime.datetime.strptime(dob_query, "%Y-%m-%d")
            except ValueError:
                return "Invalid date format. Use YYYY-MM-DD.", 400

        # build the query dynamically based on provided search criteria
        query = Patient.query
        if nhi_query:
            query = query.filter(Patient.NHI.ilike(f"%{nhi_query}%"))
        if first_name_query:
            query = query.filter(Patient.first_name.ilike(f"%{first_name_query}%"))
        if last_name_query:
            query = query.filter(Patient.last_name.ilike(f"%{last_name_query}%"))
        if dob_query:
            dob = datetime.datetime.strptime(dob_query, "%Y-%m-%d").date()
            query = query.filter(Patient.date_of_birth == dob)
          

        patients = query.all()

        return render_template("search_patients_records.html", patients=patients)

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("search_patients_records.html", patients=patients)


# route to view a specific patient's records (any user: admin, surgeon, secretary or patient themselves)
@app.route("/patients_records/<int:patient_id>", methods=["GET", "POST"])
@any_user_required
def patients_records(patient_id):
    # if patient is logged in, ensure they can only view their own records
    if session.get("patient_id") and session.get("patient_id") != patient_id:
        return "You do not have permission to view other patients' records.", 403
    
    patient = Patient.query.get_or_404(patient_id)
    surgeon_id = session.get("surgeon_id")
    surgeon = Surgeon.query.get(surgeon_id)
    appointments = Appointment.query.filter_by(patient_id=patient.id).all()
    admissions = Admission.query.filter_by(patient_id=patient.id).all()
    diagnoses = Diagnosis.query.filter_by(patient_id=patient.id).all()
    surgeries = Surgery.query.filter_by(patient_id=patient.id).all()
    complications = {}
    for surgery in surgeries:
        complications[surgery.id] = Complication.query.filter_by(surgery_id=surgery.id).all()

    return render_template("patients_records.html", patient=patient, surgeon=surgeon, appointments=appointments, admissions=admissions, diagnoses=diagnoses, surgeries=surgeries, complications=complications, now=datetime.datetime.now())



# --- Diagnosis Management Routes ---


# route to add a new diagnosis (surgeon only)
@app.route("/new_diagnosis/<int:patient_id>", methods=["GET", "POST"])
@surgeon_required

def new_diagnosis(patient_id):
    patient = Patient.query.get_or_404(patient_id)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        diagnosis_date = request.form.get("diagnosis_date")
        diagnosis_text = request.form.get("diagnosis")
        notes = request.form.get("notes")

        if not diagnosis_date or not diagnosis_text:
            return "Missing required fields", 400

        try:
            diagnosis_date = datetime.datetime.strptime(diagnosis_date, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        new_diagnosis = Diagnosis(
            patient_id=patient.id,
            surgeon_id=session.get("surgeon_id"),
            diagnosis_date=diagnosis_date,
            diagnosis=diagnosis_text,
            notes=notes
        )

        # log the addition of a new diagnosis
        log = AuditLog(
            user_id=session.get("surgeon_id"),
            action="add",
            table_name="Surgeon",
            record_id=new_diagnosis.id,
            timestamp=datetime.datetime.now(),
            details=f"Added new diagnosis for patient ID {patient.id}: {diagnosis_text}"
        )
        db.session.add(log)
        db.session.add(new_diagnosis)
        db.session.commit()

        return redirect(f"/patients_records/{patient.id}")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("new_diagnosis.html", patient=patient)

# route to edit an existing diagnosis (surgeon only)
@app.route("/edit_diagnosis/<int:diagnosis_id>", methods=["GET", "POST"])
@surgeon_required

def edit_diagnosis(diagnosis_id):
    diagnosis = Diagnosis.query.get_or_404(diagnosis_id)
    patient = Patient.query.get(diagnosis.patient_id)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        diagnosis_date = request.form.get("diagnosis_date")
        diagnosis_text = request.form.get("diagnosis")
        notes = request.form.get("notes")

        if not diagnosis_date or not diagnosis_text:
            return "Missing required fields", 400

        # Ensure the logged-in surgeon is the one who created the diagnosis
        if diagnosis.surgeon_id != session.get("surgeon_id"):
            return "You do not have permission to edit this diagnosis.", 403

         # convert diagnosis_date to a date object
        try:
            diagnosis_date = datetime.datetime.strptime(diagnosis_date, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        diagnosis.diagnosis_date = diagnosis_date
        diagnosis.diagnosis = diagnosis_text
        diagnosis.notes = notes

        # log the edit action
        log = AuditLog(
            user_id=session.get("surgeon_id"),
            action="edit",
            table_name="Surgeon",
            record_id=diagnosis.id,
            timestamp=datetime.datetime.now(),
            details=f"Edited diagnosis ID {diagnosis.id} for patient ID {patient.id}: {diagnosis_text}"
        )
        db.session.add(log)

        db.session.commit()

        flash("Diagnosis updated successfully!")
        return redirect(f"/patients_records/{patient.id}")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("edit_diagnosis.html", diagnosis=diagnosis, patient=patient)



# --- Appointment Management Routes ---


# route to add a new appointment (secretary or surgeon only)
@app.route("/new_appointment/<int:patient_id>", methods=["GET", "POST"])
@secretary_or_surgeon_required
def new_appointment(patient_id):
    patient = Patient.query.get_or_404(patient_id)

    # if secretary, get surgeon_id from form selection; if surgeon, get from session
    if session.get("secretary_id"):
        surgeons = Surgeon.query.all()
        surgeon_id = request.form.get("surgeon_id") if request.method == "POST" else None
        surgeon = Surgeon.query.get(surgeon_id) if surgeon_id else None
    else:
        surgeon_id = session.get("surgeon_id")
        surgeon = Surgeon.query.get(surgeon_id)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        appointment_date = request.form.get("appointment_date")
        reason = request.form.get("reason")

        if not appointment_date:
            return "Missing required fields", 400

        try:
            appointment_date = datetime.datetime.strptime(appointment_date, "%Y-%m-%dT%H:%M")
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DDTHH:MM.", 400

        new_appointment = Appointment(
            patient_id=patient.id,
            surgeon_id=surgeon.id if surgeon else surgeon_id,
            appointment_date=appointment_date,
            reason=reason
        )

        # log the addition of a new appointment
        log = AuditLog(
            user_id=session.get("surgeon_id") or session.get("secretary_id"),
            action="add",
            table_name="Secretary" if session.get("secretary_id") else "Surgeon",
            record_id=new_appointment.id,
            timestamp=datetime.datetime.now(),
            details=f"Added new appointment for patient ID {patient.id} on {appointment_date}"
        )
        db.session.add(log)
        db.session.add(new_appointment)
        db.session.commit()

        flash("New appointment added successfully!")
        return redirect(f"/patients_records/{patient.id}")

    return render_template("new_appointment.html", patient=patient, surgeon=surgeon, surgeons=surgeons if session.get("secretary_id") else None)


# route to edit an existing appointment (secretary or surgeon only)
@app.route("/edit_appointment/<int:appointment_id>", methods=["GET", "POST"])
@secretary_or_surgeon_required

def edit_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.get(appointment.patient_id)

    # if secretary, get surgeon_id from form selection; if surgeon, get from session
    if session.get("secretary_id"):
        surgeons = Surgeon.query.all()
        surgeon_id = request.form.get("surgeon_id") if request.method == "POST" else appointment.surgeon_id
        surgeon = Surgeon.query.get(surgeon_id) if surgeon_id else None
    else:
        surgeon_id = session.get("surgeon_id")
        surgeon = Surgeon.query.get(surgeon_id)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        appointment_date = request.form.get("appointment_date")
        reason = request.form.get("reason")

        if not appointment_date:
            return "Missing required fields", 400

        # Ensure the logged-in surgeon is the one who created the appointment
        if session.get("surgeon_id"):
            if appointment.surgeon_id != session.get("surgeon_id"):
                return "You do not have permission to edit this appointment.", 403

         # convert appointment_date to a date object
        try:
            appointment_date = datetime.datetime.strptime(appointment_date, "%Y-%m-%dT%H:%M")
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DDTHH:MM.", 400

        appointment.appointment_date = appointment_date
        appointment.reason = reason

        # log the edit action
        log = AuditLog(
            user_id=session.get("surgeon_id") or session.get("secretary_id"),
            action="edit",
            table_name="Secretary" if session.get("secretary_id") else "Surgeon",
            record_id=appointment.id,
            timestamp=datetime.datetime.now(),
            details=f"Edited appointment ID {appointment.id} for patient ID {patient.id} on {appointment_date}"
        )
        db.session.add(log)
        db.session.commit()

        flash("Appointment updated successfully!")

        return redirect(f"/patients_records/{patient.id}")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("edit_appointment.html", appointment=appointment, patient=patient, surgeon=surgeon, surgeons=surgeons if session.get("secretary_id") else None)


# route to delete a future appointment (secretary only)
@app.route("/delete_appointment/<int:appointment_id>", methods=["POST"])
@secretary_required
def delete_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    patient = Patient.query.get(appointment.patient_id)

    # Ensure the appointment date is in the future
    if appointment.appointment_date <= datetime.datetime.now():
        return "Cannot delete past or today's appointments.", 400

    # log the deletion action
    log = AuditLog(
        user_id=session.get("secretary_id"),
        action="delete",
        table_name="Secretary",
        record_id=appointment.id,
        timestamp=datetime.datetime.now(),
        details=f"Deleted appointment ID {appointment.id} for patient ID {patient.id}"
    )
    db.session.add(log)
    db.session.delete(appointment)
    db.session.commit()

    flash("Appointment deleted successfully!")
    return redirect(f"/patients_records/{patient.id}")


# search appointments (secretary and surgeon only)
@app.route("/search_appointments", methods=["GET", "POST"])
@secretary_or_surgeon_required

def search_appointments():
    appointments = []
    if session.get("surgeon_id"):
        surgeon_id = session.get("surgeon_id")
        surgeon_last_name = Surgeon.query.get(surgeon_id).last_name
    else:
        surgeon_id = None
        surgeon_last_name = None

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        patient_nhi = request.form.get("patient_NHI")
        surgeon_last_name = request.form.get("surgeon_last_name") if session.get("secretary_id") else surgeon_last_name
        date_from = request.form.get("date_from")
        date_to = request.form.get("date_to")

        try:
            if date_from:
                date_from = datetime.datetime.strptime(date_from, "%Y-%m-%d")
            if date_to:
                date_to = datetime.datetime.strptime(date_to, "%Y-%m-%d")
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400
        
        # Query the appointments based on the search criteria
        query = Appointment.query

        if patient_nhi:
            query = query.join(Patient).filter(Patient.NHI.ilike(f"%{patient_nhi}%"))
        if surgeon_last_name:
            query = query.join(Surgeon).filter(Surgeon.last_name.ilike(f"%{surgeon_last_name}%"))
        if date_from:
            query = query.filter(Appointment.appointment_date >= date_from)
        if date_to:
            query = query.filter(Appointment.appointment_date <= date_to)

        appointments = query.order_by(Appointment.appointment_date.desc()).all()

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("search_appointments.html", appointments=appointments)


# route to view appointments list (secretary and surgeon only)
@app.route("/appointments_list")
@secretary_or_surgeon_required

def appointments_list():
    date_str = request.args.get("date")
    appointments = []
    if date_str:
        try:
            date_obj = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            return "Invalid date format. Use YYYY-MM-DD.", 400

        if session.get("secretary_id"):
            appointments = Appointment.query.filter(
                db.func.date(Appointment.appointment_date) == date_obj
            ).order_by(Appointment.appointment_date.desc()).all()
        else:
            surgeon_id = session.get("surgeon_id")
            appointments = Appointment.query.filter(
                Appointment.surgeon_id == surgeon_id,
                db.func.date(Appointment.appointment_date) == date_obj
            ).order_by(Appointment.appointment_date.desc()).all()
    else:
        # Default: show all appointments
        if session.get("secretary_id"):
            appointments = Appointment.query.order_by(Appointment.appointment_date.desc()).all()
        else:
            surgeon_id = session.get("surgeon_id")
            appointments = Appointment.query.filter_by(surgeon_id=surgeon_id).order_by(Appointment.appointment_date.desc()).all()
    
    return render_template("appointments_list.html", appointments=appointments)



# --- Admission Management Routes ---


# route to add a new admission (secretary or surgeon only)
@app.route("/new_admission/<int:patient_id>", methods=["GET", "POST"])
@secretary_or_surgeon_required
def new_admission(patient_id):
    patient = Patient.query.get_or_404(patient_id)

    # if secretary, get surgeon_id from form selection; if surgeon, get from session
    if session.get("secretary_id"):
        surgeons = Surgeon.query.all()
        surgeon_id = request.form.get("surgeon_id") if request.method == "POST" else None
        surgeon = Surgeon.query.get(surgeon_id) if surgeon_id else None
    else:
        surgeon_id = session.get("surgeon_id")
        surgeon = Surgeon.query.get(surgeon_id)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        admission_date = request.form.get("admission_date")
        discharge_date = request.form.get("discharge_date")
        reason = request.form.get("reason")
        admitted_from = request.form.get("admitted_from")
        discharged_to = request.form.get("discharged_to")

        if not admission_date or not reason:
            return "Missing required fields", 400
        if not admitted_from:
            admitted_from = None
        if not discharged_to:
            discharged_to = None
    
        try:
            admission_date = datetime.datetime.strptime(admission_date, "%Y-%m-%d").date()
            if discharge_date:
                discharge_date = datetime.datetime.strptime(discharge_date, "%Y-%m-%d").date()
                if discharge_date < admission_date:
                    return "Discharge date cannot be earlier than admission date.", 400
            else:
                discharge_date = None
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        if discharge_date and discharge_date < admission_date:
            return "Discharge date cannot be earlier than admission date.", 400

         # create new admission record
        new_admission = Admission(
            patient_id=patient.id,
            surgeon_id=surgeon.id if surgeon else surgeon_id,
            admission_date=admission_date,
            discharge_date=discharge_date,
            reason=reason,
            admitted_from=admitted_from,
            discharged_to=discharged_to
        )

        # log the addition of a new admission
        log = AuditLog(
            user_id=session.get("surgeon_id") if surgeon else session.get("secretary_id"),
            action="add",
            table_name="Secretary" if session.get("secretary_id") else "Surgeon",
            record_id=new_admission.id,
            timestamp=datetime.datetime.now(),
            details=f"Added new admission for patient ID {patient.id} on {admission_date}"
        )
        db.session.add(log)
        db.session.add(new_admission)
        db.session.commit()

        flash("New admission added successfully!")
        return redirect(f"/patients_records/{patient.id}")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("new_admission.html", patient=patient, surgeon=surgeon, surgeons=surgeons if session.get("secretary_id") else None)


# route to edit an existing admission (secretary or surgeon only)
@app.route("/edit_admission/<int:admission_id>", methods=["GET", "POST"])
@secretary_or_surgeon_required
def edit_admission(admission_id):
    admission = Admission.query.get_or_404(admission_id)
    patient = Patient.query.get(admission.patient_id)

    # if secretary, get surgeon_id from form selection; if surgeon, get from session
    if session.get("secretary_id"):
        surgeons = Surgeon.query.all()
        surgeon_id = request.form.get("surgeon_id") if request.method == "POST" else admission.surgeon_id
        surgeon = Surgeon.query.get(surgeon_id) if surgeon_id else None
    else:
        surgeon_id = session.get("surgeon_id")
        surgeon = Surgeon.query.get(surgeon_id)

    if request.method == "POST":
        admission_date = request.form.get("admission_date")
        discharge_date = request.form.get("discharge_date")
        reason = request.form.get("reason")
        admitted_from = request.form.get("admitted_from")
        discharged_to = request.form.get("discharged_to")

        if not admission_date or not reason:
            return "Missing required fields", 400
        if not admitted_from:
            admitted_from = None
        if not discharged_to:
            discharged_to = None

        # Ensure the logged-in surgeon is the one who created the admission
        if session.get("surgeon_id") and admission.surgeon_id != session.get("surgeon_id"):
            return "You do not have permission to edit this admission.", 403

         # convert admission_date and discharge_date to date objects
         # and ensure discharge_date is not earlier than admission_date
         
        try:
            admission_date = datetime.datetime.strptime(admission_date, "%Y-%m-%d").date()
            if discharge_date:
                discharge_date = datetime.datetime.strptime(discharge_date, "%Y-%m-%d").date()
                if discharge_date < admission_date:
                    return "Discharge date cannot be earlier than admission date.", 400
            else:
                discharge_date = None
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        if discharge_date and discharge_date < admission_date:
            return "Discharge date cannot be earlier than admission date.", 400
        
        # update admission record
        admission.surgeon_id = surgeon.id if surgeon else surgeon_id
        admission.admission_date = admission_date
        admission.discharge_date = discharge_date
        admission.reason = reason
        admission.admitted_from = admitted_from
        admission.discharged_to = discharged_to

        # log the edit action
        log = AuditLog(
            user_id=session.get("surgeon_id") if surgeon else session.get("secretary_id"),
            action="edit",
            table_name="Secretary" if session.get("secretary_id") else "Surgeon",
            record_id=admission.id,
            timestamp=datetime.datetime.now(),
            details=f"Edited admission ID {admission.id} for patient ID {patient.id} on {admission_date}"
        )
        db.session.add(log)
        db.session.commit()

        flash("Admission updated successfully!")
        return redirect(f"/patients_records/{patient.id}")

    return render_template("edit_admission.html", admission=admission, patient=patient, surgeon=surgeon, surgeons=surgeons if session.get("secretary_id") else None)


# route to delete a future admission (secretary only)
@app.route("/delete_admission/<int:admission_id>", methods=["POST"])
@secretary_required
def delete_admission(admission_id):
    admission = Admission.query.get_or_404(admission_id)
    patient = Patient.query.get(admission.patient_id)

    # Ensure the admission date is in the future
    if admission.admission_date <= datetime.datetime.now():
        return "Cannot delete past or current admissions.", 400

    # log the deletion action
    log = AuditLog(
        user_id=session.get("secretary_id"),
        action="delete",
        table_name="Secretary",
        record_id=admission.id,
        timestamp=datetime.datetime.now(),
        details=f"Deleted admission ID {admission.id} for patient ID {patient.id}"
    )
    db.session.add(log)
    db.session.delete(admission)
    db.session.commit()

    flash("Admission deleted successfully!")
    return redirect(f"/patients_records/{patient.id}")



# --- Surgery & Complication Management Routes ---


# route to add a new surgery (surgeon only)
@app.route("/new_surgery/<int:patient_id>", methods=["GET", "POST"])
@surgeon_required

def new_surgery(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    surgeon_id = session.get("surgeon_id")
    surgeon = Surgeon.query.get(surgeon_id)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        surgery_date = request.form.get("surgery_date")
        surgery_type = request.form.get("surgery_type")
        surgery_outcome = request.form.get("surgery_outcome")
        surgery_complication = request.form.get("surgery_complication")
        surgery_complication_date = request.form.get("surgery_complication_date")

        # Validate required fields
        if not surgery_date or not surgery_type or not surgery_outcome:
            return "Missing required fields", 400
        
        if not surgery_complication or surgery_complication.strip() == "" or surgery_complication.lower() == "no" or surgery_complication.lower() == "none":
            surgery_complication = None
            surgery_complication_date = None

        if surgery_complication and (not surgery_complication_date or surgery_complication_date.strip() == ""):
            return "Please provide a date for the complication.", 400

        if surgery_complication_date and not surgery_complication:
            return "Please provide a description for the complication.", 400

        # convert surgery_date to a date object
        try:
            surgery_date = datetime.datetime.strptime(surgery_date, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        # update database with new surgery by updating class instance
        new_surgery = Surgery(
            patient_id=patient.id,
            surgeon_id=surgeon.id,
            surgery_date=surgery_date,
            surgery_type=surgery_type,
            outcome=surgery_outcome
        )

        # log the addition of a new surgery
        log = AuditLog( 
            user_id=session.get("surgeon_id"),
            action="add",
            table_name="Surgeon",
            record_id=new_surgery.id,
            timestamp=datetime.datetime.now(),
            details=f"Added new surgery for patient ID {patient.id} on {surgery_date}"
        )
        db.session.add(log)
        db.session.add(new_surgery)
        db.session.commit()

        flash("Surgery added successfully!")

        # If there's a complication, add it to the Complication table
        if surgery_complication and surgery_complication_date:
            try:
                surgery_complication_date = datetime.datetime.strptime(surgery_complication_date, "%Y-%m-%d").date()
            except (TypeError, ValueError):
                return "Invalid complication date format. Use YYYY-MM-DD.", 400

            new_complication = Complication(
                surgery_id=new_surgery.id,
                description=surgery_complication,
                complication_date=surgery_complication_date
            )

            # log the addition of a new complication
            log = AuditLog(
                user_id=session.get("surgeon_id"),
                action="add",
                table_name="Surgeon",
                record_id=new_complication.id,
                timestamp=datetime.datetime.now(),
                details=f"Added new complication for surgery ID {new_surgery.id} on {surgery_complication_date}"
            )
            db.session.add(log)
            db.session.add(new_complication)
            db.session.commit()

            flash("Complication added successfully!")

        return redirect(f"/patients_records/{patient.id}")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("new_surgery.html", patient=patient, surgeon=surgeon)


# route to edit an existing surgery (surgeon only)
@app.route("/edit_surgery/<int:surgery_id>", methods=["GET", "POST"])
@surgeon_required

def edit_surgery(surgery_id):
    surgery = Surgery.query.get_or_404(surgery_id)
    patient = Patient.query.get(surgery.patient_id)
    surgeon_id = session.get("surgeon_id")
    surgeon = Surgeon.query.get(surgeon_id)
    complications = Complication.query.filter_by(surgery_id=surgery.id).all()

    if request.method == "POST":
        surgery_date = request.form.get("surgery_date")
        surgery_type = request.form.get("surgery_type")
        surgery_outcome = request.form.get("surgery_outcome")
        surgery_complication = request.form.get("complication")
        surgery_complication_date = request.form.get("complication_date")

        if not surgery_date or not surgery_type or not surgery_outcome:
            return "Missing required fields", 400
        
        if not surgery_complication or surgery_complication.strip() == "" or surgery_complication.lower() == "no" or surgery_complication.lower() == "none":
            surgery_complication = None
            surgery_complication_date = None

        if surgery_complication and (not surgery_complication_date or surgery_complication_date.strip() == ""):
            return "Please provide a date for the complication.", 400

        if surgery_complication_date and not surgery_complication:
            return "Please provide a description for the complication.", 400

         # convert surgery_date to a date object
        try:
            surgery_date = datetime.datetime.strptime(surgery_date, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return "Invalid date format. Use YYYY-MM-DD.", 400

        # Ensure the logged-in surgeon is the one who created the surgery record
        if surgery.surgeon_id != session.get("surgeon_id"):
            return "You do not have permission to edit this surgery record.", 403

        # update surgery record
        surgery.surgery_date = surgery_date
        surgery.surgery_type = surgery_type
        surgery.outcome = surgery_outcome

        # log the edit action
        log = AuditLog(
            user_id=session.get("surgeon_id"),
            action="edit",
            table_name="Surgeon",
            record_id=surgery.id,
            timestamp=datetime.datetime.now(),
            details=f"Edited surgery ID {surgery.id} for patient ID {patient.id} on {surgery_date}"
        )
        db.session.add(log)
        db.session.commit()
        flash("Surgery updated successfully!")

        # If there's a complication, update or add it to the Complication table
        if surgery_complication and surgery_complication_date:
            try:
                surgery_complication_date = datetime.datetime.strptime(surgery_complication_date, "%Y-%m-%d").date()
            except (TypeError, ValueError):
                return "Invalid complication date format. Use YYYY-MM-DD.", 400

            new_complication = Complication(
                surgery_id=surgery.id,
                description=surgery_complication,
                complication_date=surgery_complication_date
            )

            # log the addition of a new complication
            log = AuditLog(
                user_id=session.get("surgeon_id"),
                action="add",
                table_name="Surgeon",
                record_id=new_complication.id,
                timestamp=datetime.datetime.now(),
                details=f"Added new complication for surgery ID {surgery.id} on {surgery_complication_date}"
            )
            db.session.add(log)
            db.session.add(new_complication)
            db.session.commit()

            flash("Complication added successfully!")

        elif not surgery_complication:
            # If complication field is cleared, delete existing complications
            Complication.query.filter_by(surgery_id=surgery.id).delete()
            # log the deletion of complications
            log = AuditLog(
                user_id=session.get("surgeon_id"),
                action="delete",
                table_name="Surgeon",
                record_id=surgery.id,
                timestamp=datetime.datetime.now(),
                details=f"Deleted complications for surgery ID {surgery.id}"
            )
            db.session.add(log)
            db.session.commit()

        return redirect(f"/patients_records/{patient.id}")
            
    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("edit_surgery.html", surgery=surgery, patient=patient, surgeon=surgeon, complications=complications) 


# route to access surgical logbook (surgeon only)
@app.route("/surgical_logbook")
@surgeon_required

def surgical_logbook():
    surgeon_id = session.get("surgeon_id")
    surgeon = Surgeon.query.get(surgeon_id)
    surgeries = Surgery.query.filter_by(surgeon_id=surgeon.id).all()
    complications = {}
    for surgery in surgeries:
        complications[surgery.id] = Complication.query.filter_by(surgery_id=surgery.id).all()

    return render_template("surgical_logbook.html", surgeon=surgeon, surgeries=surgeries, complications=complications)



# --- Audit Log & Admin Routes ---


# route to access audit logs (admin only)
@app.route("/audit_logs")
@admin_required
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("audit_logs.html", logs=logs)




if __name__ == "__main__":
    app.run(debug=True)