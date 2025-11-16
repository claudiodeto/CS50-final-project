import datetime
from helpers import admin_or_surgeon_required, admin_required, admin_secretary_or_surgeon_required, any_user_required, secretary_or_surgeon_required, secretary_required, surgeon_required, patient_required
from flask import Flask, flash, logging, render_template, redirect, request, session
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from models import Admin, Secretary, AuditLog, db, Surgeon, Patient, Appointment, Admission, Diagnosis, Surgery, Complication
import re
import sqlite3


from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "Eileen2025Andnow?" 

# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False  # Standard: session ends with browser
app.config["SESSION_TYPE"] = "filesystem"
Session(app)  # Initialize server-side session

# configure SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////Users/claudiodeto/Desktop/CS50/CS50_course/Week10/Final_project/CS50-final-project/static/surgery.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)  # Initialize db with your app

# initialize flask migrate
migrate = Migrate(app, db)

# configure SQLite connection
def get_db_connection():
    conn = sqlite3.connect("static/surgery.db")
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

        # Check if user needs to set a password
        if user.needs_password:
            session["pending_user_id"] = user.id
            session["pending_user_type"] = "surgeon"
            return redirect("/set_password")

        # Log the user in
        session["surgeon_id"] = user.id

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
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not password or not confirm_password:
            return "Must provide password and confirmation", 403

        if password != confirm_password:
            return "Passwords do not match", 403

        user_id = session.get("pending_user_id")
        user_type = session.get("pending_user_type")

        if user_type == "surgeon":
            user = Surgeon.query.get(user_id)
            redirect_url = "/surgeons_dashboard"
        elif user_type == "patient":
            user = Patient.query.get(user_id)
            redirect_url = "/patients_dashboard"
        elif user_type == "secretary":
            user = Secretary.query.get(user_id)
            redirect_url = "/secretaries_dashboard"
        else:
            return redirect("/")
        
        if not user:
            return "User not found", 404
        
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

        session.pop("pending_user_id", None)
        session.pop("pending_user_type", None)
        return redirect(redirect_url)


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
            return "Invalid date format. Use YYYY-MM-DD.", 400
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
        return redirect("/secretaries_list")
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
    return redirect("/secretaries_list")


# route to add a new surgeon (admin only)
@app.route("/add_surgeon", methods=["GET", "POST"])
@admin_required

def add_surgeon():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        surgeon_id = request.form.get("surgeon_id")
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
            surgeon_id=surgeon_id,
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
            details=f"Added new surgeon: {first_name} {last_name} (ID: {surgeon_id})"
        )
        db.session.add(log)
        db.session.add(new_surgeon)
        db.session.commit()
      
        # Redirect to surgeons dashboard after adding a new surgeon
        session["surgeon_id"] = new_surgeon.id  # Log in the new surgeon

        flash("New surgeon added successfully!")

        return redirect("/admin_dashboard")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("add_surgeon.html")


# route to delete a surgeon (admin only)
@app.route("/delete_surgeon/<int:surgeon_id>", methods=["POST"])
@admin_required
def delete_surgeon(surgeon_id):
    surgeon = Surgeon.query.get(surgeon_id)
    if not surgeon:
        return "Surgeon not found", 404
    
    # log the deletion of the surgeon
    log = AuditLog(
        user_id=session.get("admin_id"),
        action="delete",
        table_name="Admin",
        record_id=surgeon.id,
        timestamp=datetime.datetime.now(),
        details=f"Deleted surgeon: {surgeon.first_name} {surgeon.last_name} (ID: {surgeon.surgeon_id})"
    )
    db.session.add(log)
    db.session.delete(surgeon)
    db.session.commit()

    flash("Surgeon deleted successfully!")
    return redirect("/surgeons_list")


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
    return render_template("allowed_users.html", admins=admins, surgeons=surgeons, secretaries=secretaries)


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
            password=password
        )

        # log the addition of a new patient
        log = AuditLog(
            user_id=session.get("admin_id"),
            action="add",
            table_name="Admin",
            record_id=new_patient.id,
            timestamp=datetime.datetime.utcnow(),
            details=f"Added new patient: {first_name} {last_name} (NHI: {NHI})"
        )
        db.session.add(log)
        db.session.add(new_patient)
        db.session.commit()

        flash("New patient records added successfully!")
        return redirect("/patients_records/{}".format(new_patient.id))

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("enter_new_patient_records.html")


# route to edit an existing patient's records (admin only; surgeon can only modify medical history)
@app.route("/edit_patient/<int:patient_id>", methods=["GET", "POST"])
@admin_or_surgeon_required
def edit_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)

    if request.method == "POST":
        # Get form data
        patient.NHI = request.form.get("patient_NHI")
        patient.first_name = request.form.get("patient_first_name")
        patient.last_name = request.form.get("patient_last_name")
        patient.gender = request.form.get("gender")
        date_of_birth = request.form.get("date_of_birth")

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

    return render_template("edit_patient.html", patient_id=patient.id, patient=patient)


# route to search patients records (surgeon and admin only)
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

    return render_template("new_diagnosis.html", patient=patient)

# route to edit an existing diagnosis (surgeon only)
@app.route("/edit_diagnosis/<int:diagnosis_id>", methods=["GET", "POST"])
@surgeon_required
def edit_diagnosis(diagnosis_id):
    diagnosis = Diagnosis.query.get_or_404(diagnosis_id)
    patient = Patient.query.get(diagnosis.patient_id)

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
        if admission.surgeon_id != session.get("surgeon_id"):
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
            timestamp=datetime.now(),
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