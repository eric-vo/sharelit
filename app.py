from string import ascii_lowercase, digits

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from flask_session import Session
from helpers import login_required

VALID_USERNAME_CHARS = ascii_lowercase + digits + "_-."

app = Flask(__name__)

# Configure session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///sharelit.db")


@app.route("/")
def index():
    return render_template("index.html", username=get_username(session))


@app.route("/about")
def about():
    return render_template("about.html", username=get_username(session))


@app.route("/listings")
@login_required
def listings():
    return render_template("listings.html", username=get_username(session))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure all fields are filled
        if not (username and password):
            flash("All fields are required.")
            return render_template("login.html")

        # Query database for username
        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if not user or not check_password_hash(user[0]["hash"], password):
            flash("Invalid username and/or password.")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = user[0]["id"]

        # Redirect user to home page
        flash(f"Welcome, <strong>{username}</strong>!")
        return redirect("/listings")
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash("Logged out!")
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        full_name = request.form.get("full-name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure all fields are filled
        if not (
            username and full_name and email and password and confirmation
        ):
            flash("All fields are required.")
            return render_template("register.html")

        # Ensure username is unique
        username_matches = db.execute(
            "SELECT * FROM users WHERE username = ?", username
        )
        if username_matches:
            flash("Username already exists.")
            return render_template("register.html")

        # Ensure username only contains lowercase letters, numbers,
        # underscores, hyphens, and/or periods
        for char in username:
            if char not in VALID_USERNAME_CHARS:
                flash(
                    "Username must only contain lowercase letters, "
                    "numbers, underscores, hyphens, and/or periods."
                )
                return render_template("register.html")

        # Ensure email is unique
        email_matches = db.execute(
            "SELECT * FROM users WHERE email = ?", email
        )
        if email_matches:
            flash("Email already used.")
            return render_template("register.html")

        # Ensure password and confirmation match
        if password != confirmation:
            flash("Passwords must match.")
            return render_template("register.html")

        # Insert user into database
        user_id = db.execute(
            "INSERT INTO users (username, full_name, email, hash) "
            "VALUES (?, ?, ?, ?)",
            username,
            full_name,
            email,
            generate_password_hash(password),
        )

        # Remember which user has logged in
        session["user_id"] = user_id

        # Redirect user to home page
        flash(f"Registered as <strong>{username}</strong>!")
        return redirect("/listings")
    return render_template("register.html")


def get_username(session):
    """Get username from session"""

    if not session.get("user_id"):
        return None

    # Query database for username
    username = db.execute(
        "SELECT username FROM users WHERE id = ?", session["user_id"]
    )

    if not username:
        return None

    return username[0]["username"]
