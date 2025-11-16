import pytest
from app import app

# Fixture to create a test client
@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


# -- Test Index and Utility Routes --


# Test for the index route
def test_index(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Christchurch Hospital' in response.data

# Test for Authentication routes redirection    

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
