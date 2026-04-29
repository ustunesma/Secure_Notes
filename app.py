from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os


app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# Encryption key
KEY_FILE = "secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
    else:
        with open(KEY_FILE, "rb") as file:
            key = file.read()
    return key

cipher = Fernet(load_key())


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Password strength validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return redirect(url_for("register"))

        if not any(char.isdigit() for char in password):
            flash("Password must contain at least one number.")
            return redirect(url_for("register"))

        if not any(char.isupper() for char in password):
            flash("Password must contain at least one uppercase letter.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        role = "admin" if User.query.count() == 0 else "user"

        new_user = User(
            username=username,
            password_hash=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "POST":
        note_content = request.form["note"]

        encrypted_note = cipher.encrypt(note_content.encode()).decode()

        new_note = Note(
            encrypted_content=encrypted_note,
            user_id=current_user.id
        )

        db.session.add(new_note)
        db.session.commit()

        flash("Note saved securely.")
        return redirect(url_for("dashboard"))

    notes = Note.query.filter_by(user_id=current_user.id).all()

    decrypted_notes = []
    for note in notes:
        decrypted_text = cipher.decrypt(note.encrypted_content.encode()).decode()
        decrypted_notes.append({
            "id": note.id,
            "content": decrypted_text,
            "encrypted": note.encrypted_content
        })

    return render_template("dashboard.html", notes=decrypted_notes)


@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        return "Access Denied: You are not authorized to view this page."

    users = User.query.all()
    return render_template("admin.html", users=users)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)