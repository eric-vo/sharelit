from functools import wraps

from flask import flash, redirect, session


def login_required(f):
    """Decorate routes to require login"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to access this page.")
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function
