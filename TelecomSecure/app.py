import hashlib
import hmac
import json
import os
import secrets
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
database_url = os.getenv("DATABASE_URL", "sqlite:///telecom_secure.db")
if database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
if database_url.startswith("postgresql+psycopg://"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 180,
    }
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    password_hmac = db.Column(db.String(128), nullable=False)
    reset_token_sha1 = db.Column(db.String(40), nullable=True)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    id_number = db.Column(db.String(20), unique=True, nullable=False)


def load_policy():
    with open("password_policy.json", "r", encoding="utf-8") as f:
        return json.load(f)


def validate_password(password: str):
    policy = load_policy()
    if len(password) < policy["min_length"]:
        return False, f"Password must be at least {policy['min_length']} chars."
    if policy["require_uppercase"] and not any(c.isupper() for c in password):
        return False, "Password must include uppercase letter."
    if policy["require_lowercase"] and not any(c.islower() for c in password):
        return False, "Password must include lowercase letter."
    if policy["require_digit"] and not any(c.isdigit() for c in password):
        return False, "Password must include a digit."
    if policy["require_special"] and not any(c in policy["special_chars"] for c in password):
        return False, "Password must include special char."
    return True, "OK"


def password_to_hmac(password: str, salt: str):
    key = os.getenv("HMAC_SECRET", "hmac-dev-secret").encode()
    message = (salt + password).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def send_mail(to_email: str, subject: str, body: str):
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    mail_from = os.getenv("MAIL_FROM", "no-reply@communication-ltd.com")

    if not smtp_host:
        print(f"[DEV EMAIL] To: {to_email} | Subject: {subject} | Body: {body}")
        return

    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        values = {"username": username, "email": email}
        errors = {}

        if not username:
            errors["username"] = "Username is required."
        if not email:
            errors["email"] = "Email is required."

        valid, msg = validate_password(password)
        if not valid:
            errors["password"] = msg

        if errors:
            return render_template("register.html", values=values, errors=errors)

        if User.query.filter((User.username == username) | (User.email == email)).first():
            errors["username"] = "User or email already exists."
            return render_template("register.html", values=values, errors=errors)

        salt = secrets.token_hex(16)
        hashed = password_to_hmac(password, salt)
        db.session.add(User(username=username, email=email, salt=salt, password_hmac=hashed))
        db.session.commit()
        flash("Registration succeeded.")
        return redirect(url_for("login"))
    return render_template("register.html", values={}, errors={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        values = {"username": username}
        errors = {}

        if not username:
            errors["username"] = "Username is required."
        if not password:
            errors["password"] = "Password is required."
        if errors:
            return render_template("login.html", values=values, errors=errors)

        user = User.query.filter_by(username=username).first()
        if not user:
            errors["username"] = "User does not exist."
            return render_template("login.html", values=values, errors=errors)
        if password_to_hmac(password, user.salt) != user.password_hmac:
            errors["password"] = "Wrong password."
            return render_template("login.html", values=values, errors=errors)
        session["user_id"] = user.id
        flash("Logged in successfully.")
        return redirect(url_for("system_screen"))
    return render_template("login.html", values={}, errors={})


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.")
        return redirect(url_for("login"))
    user = User.query.get(user_id)
    if request.method == "POST":
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        values = {}
        errors = {}

        if not old_password:
            errors["old_password"] = "Current password is required."
        if not new_password:
            errors["new_password"] = "New password is required."
        if errors:
            return render_template("change_password.html", values=values, errors=errors)

        if password_to_hmac(old_password, user.salt) != user.password_hmac:
            errors["old_password"] = "Current password is wrong."
            return render_template("change_password.html", values=values, errors=errors)
        valid, msg = validate_password(new_password)
        if not valid:
            errors["new_password"] = msg
            return render_template("change_password.html", values=values, errors=errors)
        user.salt = secrets.token_hex(16)
        user.password_hmac = password_to_hmac(new_password, user.salt)
        db.session.commit()
        flash("Password changed successfully.")
        return redirect(url_for("system_screen"))
    return render_template("change_password.html", values={}, errors={})


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        values = {"username": username}
        errors = {}
        if not username:
            errors["username"] = "Username is required."
            return render_template("forgot_password.html", values=values, errors=errors)
        user = User.query.filter_by(username=username).first()
        if not user:
            errors["username"] = "User not found."
            return render_template("forgot_password.html", values=values, errors=errors)
        random_bytes = secrets.token_bytes(32)
        token_sha1 = hashlib.sha1(random_bytes).hexdigest()
        user.reset_token_sha1 = token_sha1
        db.session.commit()
        send_mail(user.email, "Communication_LTD reset code", f"Your SHA-1 reset value: {token_sha1}")
        flash("Reset value sent to your email.")
        return redirect(url_for("verify_reset"))
    return render_template("forgot_password.html", values={}, errors={})


@app.route("/verify-reset", methods=["GET", "POST"])
def verify_reset():
    if request.method == "POST":
        username = request.form["username"].strip()
        reset_value = request.form["reset_value"].strip()
        values = {"username": username, "reset_value": reset_value}
        errors = {}
        if not username:
            errors["username"] = "Username is required."
        if not reset_value:
            errors["reset_value"] = "SHA-1 value is required."
        if errors:
            return render_template("verify_reset.html", values=values, errors=errors)
        user = User.query.filter_by(username=username).first()
        if not user or user.reset_token_sha1 != reset_value:
            errors["reset_value"] = "Invalid value."
            return render_template("verify_reset.html", values=values, errors=errors)
        session["user_id"] = user.id
        user.reset_token_sha1 = None
        db.session.commit()
        flash("Verified. You can now change password.")
        return redirect(url_for("change_password"))
    return render_template("verify_reset.html", values={}, errors={})


@app.route("/system", methods=["GET", "POST"])
def system_screen():
    if not session.get("user_id"):
        flash("Please login first.")
        return redirect(url_for("login"))
    new_customer_name = None
    if request.method == "POST":
        first_name = request.form["first_name"].strip()
        last_name = request.form["last_name"].strip()
        id_number = request.form["id_number"].strip()
        values = {"first_name": first_name, "last_name": last_name, "id_number": id_number}
        errors = {}

        if not first_name:
            errors["first_name"] = "First name is required."
        if not last_name:
            errors["last_name"] = "Last name is required."
        if not id_number:
            errors["id_number"] = "ID number is required."
        elif not id_number.isdigit():
            errors["id_number"] = "ID number must contain digits only."
        elif len(id_number) not in (8, 9):
            errors["id_number"] = "ID number must be 8-9 digits."

        if Customer.query.filter_by(id_number=id_number).first():
            errors["id_number"] = "ID number already exists."

        if errors:
            return render_template("system.html", new_customer_name=None, values=values, errors=errors)

        c = Customer(first_name=first_name, last_name=last_name, id_number=id_number)
        db.session.add(c)
        db.session.commit()
        new_customer_name = f"{c.first_name} {c.last_name}"
        return render_template("system.html", new_customer_name=new_customer_name, values={}, errors={})
    return render_template("system.html", new_customer_name=new_customer_name, values={}, errors={})


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
