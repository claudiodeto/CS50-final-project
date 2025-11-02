from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum

db = SQLAlchemy()

# Database models

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Secretary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(1))
    date_of_birth = db.Column(db.Date)
    contact_info = db.Column(db.String(100))
    needs_password = db.Column(db.Boolean, default=True)

class Surgeon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    surgeon_code = db.Column(db.String(20), unique=True, nullable=True) 
    gender = db.Column(db.String(1))
    date_of_birth = db.Column(db.Date)
    contact_info = db.Column(db.String(100))
    specialty = db.Column(db.String(100))
    needs_password = db.Column(db.Boolean, default=True)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    NHI = db.Column(db.String(6), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(1))
    date_of_birth = db.Column(db.Date, nullable=False)
    contact_info = db.Column(db.String(100), nullable=False)
    emergency_contact_name = db.Column(db.String(100))
    emergency_contact_phone = db.Column(db.String(15))
    medical_history = db.Column(db.Text)
    needs_password = db.Column(db.Boolean, default=True)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    surgeon_id = db.Column(db.Integer, db.ForeignKey('surgeon.id'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.Text)
    status = db.Column(db.String(50), default='Scheduled')
    patient = db.relationship('Patient', backref='appointments')
    surgeon = db.relationship('Surgeon', backref='appointments')

class Admission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    surgeon_id = db.Column(db.Integer, db.ForeignKey('surgeon.id'), nullable=False)
    admission_date = db.Column(db.DateTime, nullable=False)
    discharge_date = db.Column(db.DateTime)
    reason = db.Column(db.Text)
    admitted_from = db.Column(
        Enum('ER', 'Clinic', 'Referral', name='admitted_from_enum'),
        nullable=True
    )
    discharged_to = db.Column(
        Enum('Home', 'Rehab', 'Nursing Home', name='discharged_to_enum'),
        nullable=True
    )
    patient = db.relationship('Patient', backref='admissions')
    surgeon = db.relationship('Surgeon', backref='admissions')

class Diagnosis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    surgeon_id = db.Column(db.Integer, db.ForeignKey('surgeon.id'), nullable=False) 
    diagnosis_date = db.Column(db.DateTime)
    diagnosis = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    patient = db.relationship('Patient', backref='diagnoses')
    surgeon = db.relationship('Surgeon', backref='diagnoses')

class Surgery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    surgeon_id = db.Column(db.Integer, db.ForeignKey('surgeon.id'), nullable=False)
    surgery_date = db.Column(db.DateTime, nullable=False)
    surgery_type = db.Column(db.String(100), nullable=False)
    outcome = db.Column(db.String(100))
    notes = db.Column(db.Text)
    patient = db.relationship('Patient', backref='surgeries')
    surgeon = db.relationship('Surgeon', backref='surgeries')

class Complication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    surgery_id = db.Column(db.Integer, db.ForeignKey('surgery.id'), nullable=False)
    complication_date = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50))
    surgery = db.relationship('Surgery', backref='complications')

# Audit Log model to track changes
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)  # ID of the user who made the change
    action = db.Column(db.String(64))  # e.g., 'create', 'update', 'delete'
    table_name = db.Column(db.String(64))  # e.g., 'Patient', 'Diagnosis'
    record_id = db.Column(db.Integer)  # ID of the affected record
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)  # Optional: what changed