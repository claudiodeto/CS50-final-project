from functools import wraps
from flask import redirect, session

# Decorator to ensure the user is logged in as an admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect("/admin_login")
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure the user is logged in as a secretary
def secretary_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("secretary_id"):
            return redirect("/secretary_login")
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure the user is logged in as a surgeon
def surgeon_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("surgeon_id")):
            return redirect("/index")
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure the user is logged in as either an admin or a surgeon
def admin_or_surgeon_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("is_admin") or session.get("surgeon_id")):
            return redirect("/login")  # or your login page
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure the user is logged in as either an admin or a secretary or a surgeon
def admin_secretary_or_surgeon_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("is_admin") or session.get("secretary_id") or session.get("surgeon_id")):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure the user is logged in as a secretary or a surgeon
def secretary_or_surgeon_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("secretary_id") or session.get("surgeon_id")):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure the user is logged in as a patient
def patient_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("patient_id"):
            return redirect("/patients_login")
        return f(*args, **kwargs)
    return decorated_function

# Decorator to ensure the user in logged in as either an admin, secretary, surgeon, or patient
def any_user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("is_admin") or session.get("secretary_id") or session.get("surgeon_id") or session.get("patient_id")):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function