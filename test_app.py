import pytest
import os
import importlib
import datetime
from models import Admission, Diagnosis, Patient, Secretary, Surgeon, Appointment, Surgery, PasswordResetToken
from werkzeug.security import generate_password_hash

# placeholder globals that the fixture will set
app = None
db = None

# Fixture to create a test client
@pytest.fixture
def client():
    # ensure test DB chosen BEFORE importing app
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    os.environ["FLASK_ENV"] = "testing"

    # import app after env var is set so SQLAlchemy binds to the test DB
    app_module = importlib.import_module("app")
    global app, db
    app = app_module.app
    db = app_module.db

    app.config['TESTING'] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]

    with app.test_client() as client:
        
        # Set up the context and initialize the database
        with app.app_context():
            # safety/ never drop or createunless using a test db
            uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
            if "sqlite:///:memory:" not in uri and not uri.endswith("test.db"):
                raise RuntimeError("Refusing to drop/create db - not a test database."
                )
            db.drop_all()
            db.create_all()

            # Create a test patient
            test_patient = Patient(
                NHI="ZQP123",
                username="testuser",
                password_hash=generate_password_hash("testpass", method="pbkdf2:sha256"),
                last_name="User",
                first_name="Test",
                date_of_birth=datetime.date(2000, 1, 1),
                contact_info="16d Test St, Christchurch",
                needs_password=False
            )
            db.session.add(test_patient)

            # Create a test secretary
            test_secretary = Secretary(
                username="testsec",
                password_hash=generate_password_hash("testpass", method="pbkdf2:sha256"),
                last_name="Secretary",
                first_name="Test",
                date_of_birth=datetime.date(1990, 1, 1),
                contact_info="123 Main St",
                needs_password=False
            )
            db.session.add(test_secretary)

            # Create a test surgeon
            test_surgeon = Surgeon(
                username="testsurgeon",
                password_hash=generate_password_hash("testpass", method="pbkdf2:sha256"),
                last_name="Surgeon",
                first_name="Test",
                surgeon_code="714235",
                date_of_birth=datetime.date(1980, 1, 1),
                contact_info="456 Main St",
                specialty="Orthopedics",
                needs_password=False
            )
            db.session.add(test_surgeon)
            
            # Create a test diagnosis
            test_diagnosis = Diagnosis(
                patient_id=1,
                surgeon_id=1,
                diagnosis_date=datetime.date(2023, 1, 1),
                diagnosis="Initial test diagnosis"
            )
            db.session.add(test_diagnosis)

            # Create a test appointment
            test_appointment = Appointment(
                patient_id=1,
                surgeon_id=1,
                appointment_date=datetime.date(2027, 1, 1),
                reason="Routine check-up",
                status="scheduled"
            )
            db.session.add(test_appointment)

            # create a test admission
            test_admission = Admission(
                patient_id=1,
                surgeon_id=1,
                admission_date=datetime.date(2028, 6, 1),
                discharge_date=datetime.date(2028, 6, 10),
                reason="Surgery",
                admitted_from="ER"
            )
            db.session.add(test_admission)

            # Create a test surgery
            test_surgery = Surgery(
                patient_id=1,
                surgeon_id=1,
                surgery_date=datetime.date(2028, 6, 2),
                surgery_type="Test Surgery",
                outcome="Successful"
            )
            db.session.add(test_surgery)

            # Commit all the test data to the database
            db.session.commit()
        yield client


# -- Test Index and Utility Routes --


# Test for the index route
def test_index(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Christchurch Hospital' in response.data



# -- Test for Authentication routes redirection

# Test for admin login redirection
def test_admin_login_redirect(client):
    response = client.get('/admin_login')
    assert response.status_code == 200
    assert b'Admin Login Portal' in response.data 

# Test for patient login redirection
def test_patient_login_redirect(client):
    response = client.get('/patients_login')
    assert response.status_code == 200
    assert b'Patient Login Portal' in response.data

# Test for secretary login redirection
def test_secretary_login_redirect(client):
    response = client.get('/secretary_login')
    assert response.status_code == 200
    assert b'Secretary Login Portal' in response.data

# Test for surgeon login redirection
def test_surgeon_login_redirect(client):
    response = client.get('/surgeons_login')
    assert response.status_code == 200
    assert b'Surgeon Login Portal' in response.data


# -- Test Authentication Logic --

# Test for invalid admin login
def test_admin_login_invalid(client):
    response = client.post('/admin_login', data={'username': 'wrong', 'password': 'wrong'})
    assert response.status_code == 200 
    assert b'Invalid credentials' in response.data 

# Test for invalid patient login
def test_patient_login_invalid(client):
    response = client.post('/patients_login', data={'username': 'wrong', 'password': 'wrong'})
    assert response.status_code == 200  
    assert b'Invalid credentials' in response.data

# Test for invalid secretary login
def test_secretary_login_invalid(client):
    response = client.post('/secretary_login', data={'username': 'wrong', 'password': 'wrong'})
    assert response.status_code == 200  
    assert b'Invalid credentials' in response.data

# Test for invalid surgeon login
def test_surgeon_login_invalid(client):
    response = client.post('/surgeons_login', data={'username': 'wrong', 'password': 'wrong'})
    assert response.status_code == 200  
    assert b'Invalid credentials' in response.data

# Test set_password route 
def test_set_password_page_loads(client):
    response = client.get("/set_password")
    assert response.status_code == 200
    assert b"Set Password" in response.data

def test_patient_login_success(client):
    response = client.post("/patients_login", data={
        "username": "testuser",
        "password": "testpass"
    }, follow_redirects=True)
    assert b"View Patients' Records" in response.data

# Test logout route
def test_logout(client):
    # Simulate login first
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    # Call logout
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Christchurch Hospital' in response.data

# Check that session is cleared after logout
    with client.session_transaction() as sess:
        assert 'is_admin' not in sess
        assert 'admin_id' not in sess

# Test forgot password route
def test_forgot_password_page_loads(client):
    response = client.get("/forgot_password")
    assert response.status_code == 200
    assert b"Forgot Password" in response.data

# Test forgot password with missing username
def test_forgot_password_missing_username(client):
    response = client.post("/forgot_password", data={
        "username": "",
        "user_type": "surgeon"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Please provide username." in response.data

# Test forgot password with invalid user type
def test_forgot_password_invalid_user_type(client):
    response = client.post("/forgot_password", data={
        "username": "testsurgeon",
        "user_type": "invalid_type"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid user type." in response.data

# Test forgot password with existent user - check for redirect and token generation
def test_forgot_password_valid_user(client):
    # simulate surgeon forgot password
    response = client.post("/forgot_password", data={
        "username": "testsurgeon",
        "user_type": "surgeon"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Reset Link Sent" in response.data or b"reset_link_sent" in response.request.path

    # Check that a token was created in the database
    with app.app_context():
        token = PasswordResetToken.query.filter_by(user_type="surgeon").first()
        assert token is not None
        assert token.user_type == "surgeon"
        assert token.user_id == 1
        assert token.token is not None
        assert len(token.token) > 0

        # check token expiration is set
        time_diff = (token.expires - datetime.datetime.now()).total_seconds()
        assert 3500 < time_diff <= 3700  # token should expire in about 1 hour

# Test forgot password creates token for patient
def test_forgot_password_creates_token_for_patient(client):

    # simulate patient forgot password
    response = client.post("/forgot_password", data={
        "username": "testuser",
        "user_type": "patient"
    }, follow_redirects=True)

    assert response.status_code == 200

    # Verify token was created
    with app.app_context():
        token = PasswordResetToken.query.filter_by(user_type="patient", user_id=1).first()
        assert token is not None
        assert token.user_type == "patient"

# Test forgot password creates token for secretary
def test_forgot_password_creates_token_for_secretary(client):

    # simulate secretary forgot password
    response = client.post("/forgot_password", data={
        "username": "testsec",
        "user_type": "secretary"
    }, follow_redirects=True)

    assert response.status_code == 200

    # Verify token was created
    with app.app_context():
        token = PasswordResetToken.query.filter_by(user_type="secretary", user_id=1).first()
        assert token is not None
        assert token.user_type == "secretary"
    
# Test reset link is stored in session
def test_forgot_password_stores_reset_link_in_session(client):
    response = client.post("/forgot_password", data={
        "username": "testsurgeon",
        "user_type": "surgeon"
    }, follow_redirects=False)

    # Should redirect to reset_link_sent
    assert response.status_code == 302
    assert "/reset_link_sent" in response.location

    # Check session for reset_link
    with client.session_transaction() as sess:
        assert "reset_link" in sess
        assert "/reset_password/" in sess["reset_link"]

# Test reset_link_sent page displays link
def test_reset_link_sent_displays_link(client):
    # First trigger forgot password to create token
    client.post("/forgot_password", data={
        "username": "testsurgeon",
        "user_type": "surgeon"
    })

    # Now access reset_link_sent
    response = client.get("/reset_link_sent", follow_redirects=True)
    assert response.status_code == 200
    assert b"reset_password" in response.data or b"Reset" in response.data

# Test forgot password with nonexistent user
def test_forgot_password_nonexistent_user(client):
    response = client.post("/forgot_password", data={
        "username": "nonexistentuser",
        "user_type": "surgeon"
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"User not found" in response.data

# Test token can be used to access reset password page
def test_reset_password_with_valid_token(client):

    # Create a token first
    client.post("/forgot_password", data={
        "username": "testsurgeon",
        "user_type": "surgeon"
    })

    # Get the token from database
    with app.app_context():
        token_record = PasswordResetToken.query.filter_by(user_type="surgeon").first()
        token = token_record.token

    # Access reset password page with token
    response = client.get(f"/reset_password/{token}")
    assert response.status_code == 200
    assert b"Reset Password" in response.data or b"New Password" in response.data

# Test reset password changes password successfully
def test_reset_password_changes_password_successfully(client):

    # Create a token first
    client.post("/forgot_password", data={
        "username": "testsurgeon",
        "user_type": "surgeon"
    })

    # Get the token from database
    with app.app_context():
        token_record = PasswordResetToken.query.filter_by(user_type="surgeon").first()
        token = token_record.token

    # Post new password using the token
    response = client.post(f"/reset_password/{token}", data={
        "new_password": "newtestpass",
        "confirm_password": "newtestpass"
    }, follow_redirects=True)

    assert response.status_code == 200
    
    # Verify can login with new password
    response = client.post("/surgeons_login", data={
        "username": "testsurgeon",
        "password": "newtestpass"
    }, follow_redirects=True)
    assert b"Dashboard" in response.data


# Test change password page loads
def test_change_password_page_loads(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1
    
    response = client.get("/change_password")
    assert response.status_code == 200
    assert b"Change Password" in response.data

# Test change password success for surgeon
def test_change_password_success_surgeon(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1
    
    response = client.post("/change_password", data={
        "current_password": "testpass",
        "new_password": "newpass123",
        "confirm_new_password": "newpass123"
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Password changed successfully" in response.data
    
    # Verify can login with new password
    client.get("/logout")
    response = client.post("/surgeons_login", data={
        "username": "testsurgeon",
        "password": "newpass123"
    }, follow_redirects=True)
    assert b"Dashboard" in response.data

# Test change password success for patient
def test_change_password_success_patient(client):
    # Simulate patient login
    with client.session_transaction() as sess:
        sess['patient_id'] = 1
    
    response = client.post("/change_password", data={
        "current_password": "testpass",
        "new_password": "newpass456",
        "confirm_new_password": "newpass456"
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Password changed successfully" in response.data

# Test change password success for secretary
def test_change_password_success_secretary(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1
    
    response = client.post("/change_password", data={
        "current_password": "testpass",
        "new_password": "newpass789",
        "confirm_new_password": "newpass789"
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Password changed successfully" in response.data

# Test change password with wrong current password
def test_change_password_wrong_current_password(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1
    
    response = client.post("/change_password", data={
        "current_password": "wrongpass",
        "new_password": "newpass123",
        "confirm_new_password": "newpass123"
    })
    
    assert response.status_code == 403
    assert b"Current password is incorrect" in response.data

# Test change password with mismatched new passwords
def test_change_password_mismatched_passwords(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1
    
    response = client.post("/change_password", data={
        "current_password": "testpass",
        "new_password": "newpass123",
        "confirm_new_password": "differentpass"
    })
    
    assert response.status_code == 403
    assert b"New passwords do not match" in response.data

# Test change password with missing fields
def test_change_password_missing_fields(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1
    
    response = client.post("/change_password", data={
        "current_password": "testpass",
        "new_password": "",
        "confirm_new_password": ""
    })
    
    assert response.status_code == 403
    assert b"All fields are required" in response.data

# Test change password without login
def test_change_password_no_login(client):
    response = client.post("/change_password", data={
        "current_password": "testpass",
        "new_password": "newpass123",
        "confirm_new_password": "newpass123"
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"No user logged in" in response.data or b"Christchurch Hospital" in response.data

# -- Test dashboard access routes --

# Admin dashboard access test
def test_admin_dashboard_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/admin_dashboard')
    assert response.status_code == 200
    assert b'Admin Dashboard' in response.data

# Secretary dashboard access test
def test_secretary_dashboard_access(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1

    response = client.get('/secretaries_dashboard')
    assert response.status_code == 200
    assert b'Secretaries\' Dashboard' in response.data

# Surgeon dashboard access test
def test_surgeon_dashboard_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1

    response = client.get('/surgeons_dashboard')
    assert response.status_code == 200
    assert b'Surgeons\' Dashboard' in response.data


# -- Test user management routes (Admin only) --

# Test route to add a new secretary
def test_add_secretary_page_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/add_secretary')
    assert response.status_code == 200
    assert b'Add Secretaries' in response.data

def test_add_secretary_success(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.post('/add_secretary', data={
        'username': 'newsecretary',
        'password': 'newpass',
        'confirm_password': 'newpass',
        'first_name': 'New',
        'last_name': 'Secretary',
        'gender': 'F',
        'date_of_birth': '1990-01-01',
        'contact_info': '123 Main St'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Allowed Users' in response.data

# Test route to delete a secretary  
def test_delete_secretary_success(client):
    # Get the test secretary's ID
    with app.app_context():
        secretary = Secretary.query.filter_by(username="testsec").first()
        secretary_id = secretary.id

    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1
    
    # Send delete request
    response = client.post(f'/delete_secretary/{secretary_id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'Allowed Users' in response.data

# Test route to add a new surgeon
def test_add_surgeon_page_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/add_surgeon')
    assert response.status_code == 200
    assert b'Add Surgeons' in response.data

def test_add_surgeon_success(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.post('/add_surgeon', data={
        'username': 'newsurgeon',
        'password': 'newpass',
        'confirm_password': 'newpass',
        'first_name': 'New',
        'last_name': 'Surgeon',
        'surgeon_id': '714235',
        'gender': 'M',
        'date_of_birth': '1980-01-01',
        'contact_info': '456 Main St',
        'specialty': 'Cardiology'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'New surgeon added successfully' in response.data

# Test route to delete a surgeon  
def test_delete_surgeon_success(client):
    # Get the test surgeon's ID
    with app.app_context():
        surgeon = Surgeon.query.filter_by(username="testsurgeon").first()
        print(surgeon.id)
        surgeon_id = surgeon.id

    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1
    
    # Send delete request
    response = client.post(f'/delete_surgeon/{surgeon_id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'Allowed Users' in response.data

# Test route to view surgeons list
def test_view_surgeons_list_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/surgeons_list')
    assert response.status_code == 200
    assert b'Surgeons\' list' in response.data

# Test route to view secretaries list
def test_view_secretaries_list_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/secretaries_list')
    assert response.status_code == 200
    assert b'Secretaries\' list' in response.data

# Test route to view allowed users list
def test_view_allowed_users_list_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/allowed_users')
    assert response.status_code == 200
    assert b'Allowed Users' in response.data


# -- Test patient management routes --

# Test route to enter new patient record
def test_enter_new_patient_record_page_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/enter_new_patient_records')
    assert response.status_code == 200
    assert b'Enter New Patient Records' in response.data

def test_enter_new_patient_record_success(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.post('/enter_new_patient_records', data={
        'patient_NHI': 'ZTQ487',
        'patient_first_name': 'New',
        'patient_last_name': 'Patient',
        'gender': 'M',
        'date_of_birth': '1995-05-05',
        'contact_info': '789 Main St'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Allowed Users' in response.data

# Test route to edit an existing patient record
def test_edit_patient_record_page_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.get(f'/edit_patient/{patient_id}')
    assert response.status_code == 200
    assert b'Edit Patient' in response.data

def test_edit_patient_record_success(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.post(f'/edit_patient/{patient_id}', data={
        'patient_NHI': 'ZQP123',
        'patient_first_name': 'Test',
        'patient_last_name': 'User',
        'gender': 'M',
        'date_of_birth': '2000-01-01',
        'contact_info': '14d Test St, Christchurch',
        'medical_history': 'Updated medical history',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to delete a patient record  
def test_delete_patient_record_success(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1
    
    # Get the test patient's ID
    with app.app_context():
        patient = Patient. query.filter_by(username="testuser").first()
        patient_id = patient.id

    # Send delete request
    response = client.post(f'/delete_patient/{patient_id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'Allowed Users' in response.data

# Test route to search patient records
def test_search_patient_records_page_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/search_patients_records')
    assert response.status_code == 200
    assert b'Search for Patients\' Records' in response.data

def test_search_patient_records_success(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.post('/search_patients_records', data={
        'NHI': 'ZQP123'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Test' in response.data  

# Test route to view a patient's record
def test_view_patient_record_page_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.get(f'/patients_records/{patient_id}')
    assert response.status_code == 200
    assert b'Test' in response.data

# -- Test Diagnosis Management Routes --

# Test route to enter new diagnosis (surgeon only)
def test_enter_new_diagnosis_page_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.get(f'/new_diagnosis/{patient_id}')
    assert response.status_code == 200
    assert b'New Diagnosis' in response.data

def test_enter_new_diagnosis_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.post(f'/new_diagnosis/{patient_id}', data={
        'diagnosis_date': '2024-01-01',
        'diagnosis': 'Test diagnosis entry'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to edit an existing diagnosis (surgeon only)
def test_edit_diagnosis_page_access(client):

    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.get(f'/edit_diagnosis/{patient_id}')
    assert response.status_code == 200
    assert b'Edit Diagnosis' in response.data

def test_edit_diagnosis_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    # Get the test diagnosis ID
    with app.app_context():
        diagnosis = Diagnosis.query.filter_by(patient_id=patient_id).first()
        diagnosis_id = diagnosis.id

    response = client.post(f'/edit_diagnosis/{diagnosis_id}', data={
        'diagnosis_date': '2024-01-02',
        'diagnosis': 'Updated test diagnosis entry'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# -- Test Appointment Management Routes --

# Test route to schedule a new appointment (secretary or surgeon only)
def test_schedule_appointment_page_access(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.get(f'/new_appointment/{patient_id}')
    assert response.status_code == 200
    assert b'New Appointment' in response.data

def test_schedule_appointment_success(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1
    
    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.post(f'/new_appointment/{patient_id}', data={
        'surgeon_id': 1,
        'appointment_date': '2024-01-01T09:00',
        'reason': 'Test appointment entry'
    }, follow_redirects=True)
    print(response.data)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to edit an existing appointment (secretary or surgeon only)
def test_edit_appointment_page_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    # Get the test appointment ID
    with app.app_context():
        appointment = Appointment.query.filter_by(patient_id=patient_id).first()
        appointment_id = appointment.id

    response = client.get(f'/edit_appointment/{appointment_id}')
    assert response.status_code == 200
    assert b'Edit Appointment' in response.data

def test_edit_appointment_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    # Get the test appointment ID
    with app.app_context():
        appointment = Appointment.query.filter_by(patient_id=patient_id).first()
        appointment_id = appointment.id

    response = client.post(f'/edit_appointment/{appointment_id}', data={
        'appointment_date': '2024-01-02T10:00',
        'reason': 'Updated test appointment entry',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to cancel an appointment (secretary only)
def test_delete_appointment_success(client):
    # Get the test appointment ID
    with app.app_context():
        appointment = Appointment.query.first()
        appointment_id = appointment.id

    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1
    
    # Send delete request
    response = client.post(f'/delete_appointment/{appointment_id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test search appointments page access (secretary or surgeon only)
def test_search_appointments_page_access(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1

    response = client.get('/search_appointments')
    assert response.status_code == 200
    assert b'Search Appointments' in response.data

def test_search_appointments_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1

    response = client.post('/search_appointments', data={
        'patient_NHI': 'ZQP123',
        'date_from': '2024-01-01',
        'date_to': '2027-12-31'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Test' in response.data

# Test route to view appointments list (secretary or surgeon only)
def test_view_appointments_list_page_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1

    response = client.get('/appointments_list')
    assert response.status_code == 200
    assert b'View Appointments' in response.data

def test_view_appointments_list_success(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1

    response = client.get(f'/appointments_list?date_from=2024-01-01 09:00&date_to=2027-12-31 17:00')
    assert response.status_code == 200
    assert b'ZQP123' in response.data

# -- Test Admission Management Routes --

# Test route to add a new admission (secretary or surgeon only)

def test_add_admission_page_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.get(f'/new_admission/{patient_id}')
    assert response.status_code == 200
    assert b'New Admission' in response.data

def test_add_admission_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.post(f'/new_admission/{patient_id}', data={
        'admission_date': '2024-02-01',
        'discharge_date': '2024-02-10',
        'reason': 'Test admission entry',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to edit an existing admission (secretary or surgeon only)
def test_edit_admission_page_access(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1

    # Get the test admission ID
    with app.app_context():
        admission = Admission.query.first()
        admission_id = admission.id

    response = client.get(f'/edit_admission/{admission_id}')
    assert response.status_code == 200
    assert b'Edit Admission' in response.data

def test_edit_admission_success(client):
    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1

    # Get the test admission ID
    with app.app_context():
        admission = Admission.query.first()
        admission_id = admission.id

    response = client.post(f'/edit_admission/{admission_id}', data={
        'surgeon_id': 1,
        'admission_date': '2024-02-01',
        'discharge_date': '2024-02-10',
        'reason': 'Updated admission entry',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to delete an admission (secretary only)
def test_delete_admission_success(client):
    # Get the test admission ID
    with app.app_context():
        admission = Admission.query.first()
        admission_id = admission.id

    # Simulate secretary login
    with client.session_transaction() as sess:
        sess['secretary_id'] = 1
    
    # Send delete request
    response = client.post(f'/delete_admission/{admission_id}', follow_redirects=True)
    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# -- Test surgery and complication management routes --

# Test route to add a new surgery (surgeon only)
def test_add_surgery_page_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.get(f'/new_surgery/{patient_id}')
    assert response.status_code == 200
    assert b'New Surgery' in response.data

def test_add_surgery_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.post(f'/new_surgery/{patient_id}', data={
        'surgery_date': '2024-03-01',
        'surgery_type': 'Test surgery type',
        'surgery_outcome': 'Successful',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

def test_add_surgery_with_complication_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test patient's ID
    with app.app_context():
        patient = Patient.query.filter_by(username="testuser").first()
        patient_id = patient.id

    response = client.post(f'/new_surgery/{patient_id}', data={
        'surgery_date': '2024-03-01',
        'surgery_type': 'Test surgery type',
        'surgery_outcome': 'Complicated',
        'surgery_complication': 'Test complication details',
        'surgery_complication_date': '2024-03-02'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to edit an existing surgery (surgeon only)
def test_edit_surgery_page_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test surgery ID
    with app.app_context():
        surgery = Surgery.query.first()
        surgery_id = surgery.id

    response = client.get(f'/edit_surgery/{surgery_id}')
    assert response.status_code == 200
    assert b'Edit Surgery' in response.data

def test_edit_surgery_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test surgery ID
    with app.app_context():
        surgery = Surgery.query.first()
        surgery_id = surgery.id

    response = client.post(f'/edit_surgery/{surgery_id}', data={
        'surgery_date': '2024-03-05',
        'surgery_type': 'Updated surgery type',
        'surgery_outcome': 'Successful',
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

def test_edit_surgery_with_complication_success(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    # Get the test surgery ID
    with app.app_context():
        surgery = Surgery.query.first()
        surgery_id = surgery.id

    response = client.post(f'/edit_surgery/{surgery_id}', data={
        'surgery_date': '2024-03-05',
        'surgery_type': 'Updated surgery type',
        'surgery_outcome': 'Complicated',
        'surgery_complication': 'Updated complication details',
        'surgery_complication_date': '2024-03-06'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'View Patients\' Records' in response.data

# Test route to access surgical logbook (surgeon only)
def test_surgical_logbook_page_access(client):
    # Simulate surgeon login
    with client.session_transaction() as sess:
        sess['is_surgeon'] = True
        sess['surgeon_id'] = 1

    response = client.get('/surgical_logbook')
    assert response.status_code == 200
    assert b'Surgical Logbook' in response.data

# -- Test Audit Log Route --
def test_audit_log_page_access(client):
    # Simulate admin login
    with client.session_transaction() as sess:
        sess['is_admin'] = True
        sess['admin_id'] = 1

    response = client.get('/audit_logs')
    assert response.status_code == 200
    assert b'Audit Log' in response.data