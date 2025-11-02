CREATE TABLE surgeons (
    id INTEGER PRIMARY KEY CHECK(id GLOB '[0-9]*' AND LENGTH(id) <= 6),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    gender VARCHAR(1),
    date_of_birth DATE,
    contact_info VARCHAR(100),
    specialty VARCHAR(100)
);

CREATE TABLE patients (
    id INTEGER PRIMARY KEY,
    NHI VARCHAR(6) UNIQUE NOT NULL CHECK(NHI GLOB '[A-Z][A-Z][A-Z][0-9][0-9][0-9]'),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    gender TEXT CHECK(M, F, NULL),
    date_of_birth DATE,
    contact_info VARCHAR(100),
    emergency_contact_name VARCHAR(100),
    emergency_contact_phone VARCHAR(15),
    medical_history TEXT
);

CREATE TABLE appointments (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    surgeon_id INTEGER NOT NULL,
    appointment_date DATETIME NOT NULL,
    reason TEXT,
    status VARCHAR(50) DEFAULT 'Scheduled',
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (surgeon_id) REFERENCES surgeons(id)
);

CREATE TABLE admissions (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    surgeon_id INTEGER NOT NULL,
    admission_date DATETIME NOT NULL,
    discharge_date DATETIME,
    reason TEXT,
    admitted_from VARCHAR(100) CHECK(admitted_from IN ('ER', 'Clinic', 'Referral')),
    discharged_to VARCHAR(100) CHECK(discharged_to IN ('Home', 'Rehab', 'Nursing Home')),
    FOREIGN KEY (patient_id) REFERENCES patients(id)
    FOREIGN KEY (surgeon_id) REFERENCES surgeons(id)
);

CREATE TABLE diagnosis (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    diagnosis_date DATETIME NOT NULL,
    diagnosis TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE surgeries (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    surgeon_id INTEGER NOT NULL,
    surgery_date DATETIME NOT NULL,
    surgery_type VARCHAR(100),
    outcome VARCHAR(100),
    notes TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (surgeon_id) REFERENCES surgeons(id)
);

CREATE TABLE complications (
    id INTEGER PRIMARY KEY,
    surgery_id INTEGER NOT NULL,
    complication_date DATETIME NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(50) CHECK(severity IN ('Mild', 'Moderate', 'Severe')),
    FOREIGN KEY (surgery_id) REFERENCES surgeries(id)
);