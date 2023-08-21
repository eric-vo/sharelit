from datetime import datetime
from string import ascii_lowercase, digits

from cs50 import SQL
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)
from flask_socketio import SocketIO, emit
from werkzeug.security import check_password_hash, generate_password_hash

from flask_session import Session
from helpers import login_required

VALID_USERNAME_CHARS = ascii_lowercase + digits + "_-."

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"
socketio = SocketIO(app, async_mode="threading")

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


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title = request.form.get("title")
        author = request.form.get("author")
        description = request.form.get("description")

        # Ensure all fields are filled
        if not (title and author and description):
            flash("All fields are required.")
            return render_template(
                "create.html", username=get_username(session)
            )
        db.execute(
            "INSERT INTO listings (user_id, title, author,"
            "description) VALUES (?, ?, ?, ?)",
            session["user_id"],
            title,
            author,
            description,
        )
        flash("Created listing!")
        return redirect("/listings")

    return render_template("create.html", username=get_username(session))


@app.route("/listings", methods=["GET", "POST"])
def listings():
    listings = get_books()
    # Get names of users who created listings using JOIN
    listing_users = db.execute(
        "SELECT users.id, username FROM users JOIN listings ON "
        "users.id = listings.user_id"
    )

    if request.method == "POST":
        # Get form data
        listing_id = request.form.get("listing-id")
        creator_id = request.form.get("creator-id")

        # Ensure person deleting listing is the creator
        if session["user_id"] != int(creator_id):
            flash("You can only delete your own listings.")
            return redirect("/listings")

        # Delete listing
        db.execute("DELETE FROM listings WHERE id = ?", listing_id)
        flash("Deleted listing!")
        return redirect("/listings")

    return render_template(
        "listings.html",
        listings_and_users=zip(listings, listing_users),
        username=get_username(session),
    )


@app.route("/listings/<int:listing_id>", methods=["GET", "POST"])
@login_required
def listing(listing_id):
    listing = db.execute("SELECT * FROM listings WHERE id = ?", listing_id)
    listing_user = db.execute(
        "SELECT users.username, users.id FROM users JOIN listings ON "
        "users.id = listings.user_id WHERE listings.id = ?",
        listing_id,
    )

    if request.method == "POST":
        # Get form data
        duration = request.form.get("duration")
        time_period = request.form.get("time-period")

        # Ensure user requesting is not the creator
        if session["user_id"] == listing_user[0]["id"]:
            flash("You cannot request your own listing.")
            return render_template(
                "listing.html",
                listing=listing[0],
                listing_user=listing_user[0],
                username=get_username(session),
            )

        # Ensure all fields are filled
        if not (duration and time_period):
            flash("All fields are required.")
            return render_template(
                "listing.html",
                listing=listing[0],
                listing_user=listing_user[0],
                username=get_username(session),
            )

        # Insert into requests table (replace with actual table and columns)
        db.execute(
            "INSERT INTO requests "
            "(user_id, listing_id, duration, time_period) "
            "VALUES (?, ?, ?, ?)",
            session["user_id"],
            listing_id,
            duration,
            time_period,
        )

        # Message the user from current user about the request
        message = (
            "I would like to borrow your book for "
            + duration
            + " "
            + time_period
            + "."
        )
        db.execute(
            "INSERT INTO messages "
            "(from_user_id, to_user_id, message) VALUES (?, ?, ?)",
            session["user_id"],
            listing_user[0]["id"],
            message,
        )
        flash("Sent request!")
        return redirect("/messages")

    return render_template(
        "listing.html",
        listing=listing[0],
        listing_user=listing_user[0],
        username=get_username(session),
    )


@app.route("/requests")
@login_required
def requests():
    return render_template(
        "requests.html", requests=requests, username=get_username(session)
    )


@app.route("/chat")
@login_required
def chat():
    return render_template("chat.html", username=get_username(session))


@app.route("/messages")
@login_required
def messages():
    conversations = get_user_conversations(session)
    return render_template(
        "messages.html",
        conversations=conversations,
        username=get_username(session),
    )


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


@app.route("/profile/<username>")
def profile(username):
    user = db.execute("SELECT * FROM users WHERE username = ?", username)
    return render_template("profile.html", user=user[0], username=username)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        full_name = request.form.get("full-name")
        city_state_country = request.form.get("city-state-country")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure all fields are filled
        if not (
            username
            and full_name
            and city_state_country
            and email
            and password
            and confirmation
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
            "INSERT INTO users "
            "(username, full_name, city_state_country, email, hash) "
            "VALUES (?, ?, ?, ?, ?)",
            username,
            full_name,
            city_state_country,
            email,
            generate_password_hash(password),
        )

        # Remember which user has logged in
        session["user_id"] = user_id

        # Redirect user to home page
        flash(f"Registered as <strong>{username}</strong>!")
        return redirect("/listings")
    return render_template("register.html")


# Listen to the 'send_message' event from the client
@socketio.on("send_message")
def handle_send_message(data):
    from_user_id = session["user_id"]
    to_user_id = data["to_user_id"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = data["message"]

    # Insert message into the database
    # (update with the actual table and columns)
    db.execute(
        "INSERT INTO messages "
        "(from_user_id, to_user_id, message, timestamp) VALUES (?, ?, ?, ?)",
        from_user_id,
        to_user_id,
        message,
        timestamp,
    )

    # Create a message object for broadcasting
    message = {
        "message": message,
        "timestamp": timestamp,
        "from_user_id": from_user_id,
        "to_user_id": to_user_id,
    }

    # Emit the message to all connected clients
    socketio.emit("receive_message", message)


@app.route("/get_messages")
def get_messages():
    messages = db.execute(
        "SELECT * FROM messages WHERE from_user_id = ? OR to_user_id = ?",
        session["user_id"],
        session["user_id"],
    )
    return jsonify(messages)


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


def get_books():
    """Get books from database"""

    books = db.execute("SELECT * FROM listings")

    return books


def get_user_conversations(session):
    messages = db.execute(
        "SELECT * FROM messages WHERE from_user_id = ? OR to_user_id = ?",
        session["user_id"],
        session["user_id"],
    )

    conversations = {}
    for message in messages:
        other_user_id = (
            message["from_user_id"]
            if message["from_user_id"] != session["user_id"]
            else message["to_user_id"]
        )
        other_user = db.execute(
            "SELECT username FROM users WHERE id = ?", other_user_id
        )[0]

        # Create a conversation entry if it doesn't exist
        if other_user_id not in conversations:
            conversations[other_user_id] = {
                "id": other_user_id,
                "name": other_user["username"],
                "messages": [],
            }

        # Append the message to the conversation's messages list
        conversations[other_user_id]["messages"].append(
            {
                "text": message["message"],
                "timestamp": message["timestamp"],
                "from_user_id": message["from_user_id"],
                "to_user_id": message["to_user_id"],
            }
        )

    # Convert the conversations dictionary to a list
    conversations_list = list(conversations.values())

    return conversations_list


@socketio.on("request_conversation")
def handle_request_conversation(data):
    conversation_id = data["conversation_id"]
    messages = db.execute(
        "SELECT * FROM messages WHERE conversation_id = ?", conversation_id
    )

    for message in messages:
        # Format and emit each message
        formatted_message = {
            "message": message["message"],
            "timestamp": message["timestamp"],
            "username": get_username(message["user_id"]),
        }
        emit("receive_message", formatted_message)


if __name__ == "__main__":
    socketio.run(app)
    print("Running app.py")
