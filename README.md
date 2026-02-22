# Hospital Management System

A comprehensive web-based hospital management system built with Flask for CS50's Final Project.

## Video Demo

[Link to YouTube video - to be added]

## Description

This application provides a complete hospital management solution with role-based access control for administrators, surgeons, secretaries, and patients. It manages patient records, appointments, admissions, surgeries, diagnoses, and includes comprehensive audit logging.

Built by a neurosurgeon to demonstrate practical software development skills acquired through CS50.


## Live Demo

🌐 **[Your Deployed URL Here]**

### Quick Start Guide

1. **Reset the database** (optional, if previous users added test data):
   - Visit the homepage
   - Click the yellow "Reset to Demo State" button
   - Confirm the reset

2. **Login as Admin**:
   - Username: `admin`
   - Password: `Test1234!`

3. **Create test users to explore the system**:
   - From the Admin Dashboard → "View Allowed Users"
   - Click "Add New Surgeon" (example: Dr. Smith, Neurosurgery)
   - Click "Add New Secretary" (example: Jane Doe)
   - Click "Add New Patient" (example: John Patient, NHI: ABC123)

4. **Explore different user roles**:
   - Logout and login with each user type to see role-based features
   - **Surgeon**: Add diagnoses, record surgeries, view surgical logbook
   - **Secretary**: Schedule appointments, manage admissions
   - **Patient**: View personal medical records (read-only)

### Demo Workflow Example

1. **Admin** → Create surgeon, secretary, and patient
2. **Secretary** → Schedule appointment for patient
3. **Surgeon** → Add diagnosis and surgery
4. **Patient** → View complete medical history
5. **Admin** → Review audit logs of all activities

**Note**: The reset button allows anyone to start fresh with a clean database!


## Features

### User Roles & Permissions

- **Admin**: Full system access, user management, audit logs
- **Surgeon**: Patient records access, diagnoses, surgeries, surgical logbook
- **Secretary**: Appointment scheduling, admissions management, patient search
- **Patient**: View personal medical records and history

### Core Functionality

- **Patient Management**: Create, edit, search, and view comprehensive patient records
- **Appointment Scheduling**: Book and manage appointments between patients and surgeons
- **Admission Tracking**: Record hospital admissions and discharges with detailed information
- **Surgical Records**: Document surgeries, outcomes, and complications
- **Diagnosis Management**: Record and update patient diagnoses with surgeon attribution
- **Password Management**: Secure password reset with token-based authentication (1-hour expiration)
- **Audit Logging**: Track all system actions for accountability and security
- **Surgical Logbook**: Personal surgical record tracking for individual surgeons

## Technologies Used

- **Backend**: Python 3.9, Flask 3.x
- **Database**: SQLite with SQLAlchemy 2.x ORM
- **Authentication**: Werkzeug password hashing (PBKDF2-SHA256)
- **Session Management**: Flask-Session (server-side sessions)
- **Database Migrations**: Flask-Migrate
- **Frontend**: HTML5, Bootstrap 5, Jinja2 templates
- **Testing**: Pytest with comprehensive test coverage

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Setup Instructions

1. **Clone the repository:**

```bash
git clone https://github.com/claudiodeto/CS50-final-project.git
cd CS50-final-project
```

2. **Create a virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

4. **Initialize the database:**

```bash
python create_db.py
python create_admin.py
```

Follow the prompts to create your admin account.

**Note**: The deployed demo already has an admin account (username: `admin`, password: `Test1234!`).

5. **Run the application:**
```bash
flask run
```

6. **Access the application:**

Open your browser and navigate to http://127.0.0.1:5000

## Usage

Password: Test1234!
User workflow:

### As an Admin:

Log in via Admin Login Portal
Add surgeons and secretaries via user management
Create patient accounts with login credentials
View audit logs for system activity
Manage all users and records

### As a Surgeon:

Log in via Surgeon Login Portal
Search and view patient records
Add diagnoses with detailed notes
Record surgeries and complications
Access personal surgical logbook

### As a Secretary:

Log in via Secretary Login Portal
Schedule appointments between patients and surgeons
Manage hospital admissions and discharges
Search patient records for administrative purposes

### As a Patient:

Log in via Patient Login Portal
View complete medical history
See scheduled appointments
Review diagnoses and surgical records
Change password for security

#### Password Reset
The password reset feature generates secure tokens that expire after 1 hour. For demonstration purposes, the reset link is displayed on-screen. In a production environment, this would be sent via email.

#### Testing
- Run the complete test suite: 
pytest test_app.py -v

- Run specific test categories: 
pytest test_app.py -k "password" -v     # Password tests
pytest test_app.py -k "patient" -v      # Patient management tests
pytest test_app.py -k "appointment" -v  # Appointment tests

## Project structure

CS50-final-project/
├── app.py                 # Main application with routes
├── models.py              # SQLAlchemy database models
├── helpers.py             # Access control decorators
├── create_db.py           # Database initialization
├── create_admin.py        # Admin account creation
├── test_app.py            # Pytest test suite
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── templates/             # HTML templates
├── static/                # Static files
├── flask_session/         # Server-side session storage
└── migrations/            # Database migration files

## Database Schema

Main Tables:

admin - System administrators
surgeon - Medical staff with surgical privileges
secretary - Administrative staff
patient - Patient records and credentials
appointment - Scheduled appointments
admission - Hospital admissions/discharges
surgery - Surgical procedures and outcomes
diagnosis - Patient diagnoses
complication - Surgery-related complications
audit_log - System activity tracking
password_reset_token - Secure password reset tokens

## Security Features

Password hashing with PBKDF2-SHA256 and salt
Role-based access control with custom decorators
Server-side session management
SQL injection protection via SQLAlchemy ORM
Token-based password reset with expiration
Comprehensive audit logging
Input validation and error handling


## Design Decisions

### Password Reset Implementation
The password reset displays links on-screen rather than sending emails. This design choice allows CS50 evaluators and visitors to easily test the functionality without requiring email server configuration.

### Role-Based Access Control
Used Python decorators to enforce permissions cleanly and reduce code duplication.

### Database Choice
SQLite was chosen for simplicity and portability, making it easy for evaluators to run the project without external database setup.

## Known Limitations

- No email integration (password reset links displayed on-screen)
- No real-time notifications
- Limited to single-hospital use case
- No mobile-responsive optimizations

## Future Enhancements

- Email integration for password reset and notifications
- Advanced reporting and analytics dashboard
- Medical imaging integration
- Mobile-responsive design improvements
- Multi-hospital support
- REST API for third-party integrations

## Author

Claudio De Tommasi

Neurosurgeon & CS50 Student
GitHub: @claudiodeto

## Acknowledgments

Harvard's CS50 course and staff
Flask and SQLAlchemy documentation
Bootstrap framework
GitHub Copilot for development assistance

## License

This project is submitted as part of CS50's Final Project requirements (2026).
