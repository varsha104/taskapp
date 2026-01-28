from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import re
import os

app = Flask(__name__)
app.secret_key = "secret123"

# ================= DATABASE CONFIG (POSTGRESQL ONLY) =================

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. PostgreSQL is required!")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ================= MODELS =================

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50))
    lname = db.Column(db.String(50))
    contact = db.Column(db.String(10))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    status = db.Column(db.String(20), default="Pending")
    priority = db.Column(db.String(20))
    deadline = db.Column(db.String(20))
    completed_at = db.Column(db.String(50))

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    user = db.relationship("User", foreign_keys=[user_id])
    admin = db.relationship("User", foreign_keys=[admin_id])

# ================= LOGIN =================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form["role"]
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(
            email=email,
            is_admin=True if role == "admin" else False
        ).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session.clear()
            session["name"] = user.fname
            session["user_id"] = user.id

            if role == "admin":
                session["admin"] = True
                session["admin_id"] = user.id
                return redirect("/admin")
            return redirect("/dashboard")

        flash("Invalid credentials")
    return render_template("login.html")

# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if request.form["password"] != request.form["confirm_password"]:
            flash("Passwords do not match")
            return redirect("/register")

        if not re.fullmatch(r"\d{10}", request.form["contact"]):
            flash("Contact must be exactly 10 digits")
            return redirect("/register")

        email = request.form["email"]
        if User.query.filter_by(email=email).first():
            flash("Email already exists")
            return redirect("/register")

        role = request.form["role"]

        user = User(
            fname=request.form["fname"],
            lname=request.form["lname"],
            contact=request.form["contact"],
            email=email,
            password=bcrypt.generate_password_hash(
                request.form["password"]
            ).decode("utf-8"),
            is_admin=True if role == "admin" else False,
        )

        db.session.add(user)
        db.session.commit()
        flash("Registration successful")
        return redirect("/")

    return render_template("register.html")

# ================= FORGOT PASSWORD (✅ FIXED) =================

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]
        new_password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect("/forgot")

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email not found")
            return redirect("/forgot")

        user.password = bcrypt.generate_password_hash(
            new_password
        ).decode("utf-8")

        db.session.commit()
        flash("Password reset successful. Please login.")
        return redirect("/")

    return render_template("forgot.html")

# ================= ADMIN DASHBOARD =================

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("admin"):
        return redirect("/")

    users = User.query.filter_by(is_admin=False).all()

    if request.method == "POST":
        for uid in request.form.getlist("user_ids"):
            task = Task(
                title=request.form["title"],
                priority=request.form["priority"],
                deadline=request.form["deadline"],
                user_id=uid,
                admin_id=session["admin_id"],
            )
            db.session.add(task)

        db.session.commit()
        flash("Task assigned successfully")

    tasks = Task.query.filter_by(admin_id=session["admin_id"]).all()
    return render_template("admin.html", users=users, tasks=tasks)

# ================= EDIT TASK =================

@app.route("/edit_task/<int:id>", methods=["GET", "POST"])
def edit_task(id):
    if not session.get("admin"):
        return redirect("/")

    task = Task.query.get_or_404(id)

    if task.admin_id != session.get("admin_id"):
        flash("Unauthorized access")
        return redirect("/admin")

    if request.method == "POST":
        task.title = request.form["title"]
        task.priority = request.form["priority"]
        task.deadline = request.form["deadline"]
        db.session.commit()
        flash("Task updated successfully")
        return redirect("/admin")

    return render_template("edit_task.html", task=task)

# ================= DELETE TASK =================

@app.route("/delete_task/<int:id>")
def delete_task(id):
    if not session.get("admin"):
        return redirect("/")

    task = Task.query.get_or_404(id)

    if task.admin_id != session.get("admin_id"):
        flash("Unauthorized action")
        return redirect("/admin")

    db.session.delete(task)
    db.session.commit()
    flash("Task deleted successfully")
    return redirect("/admin")

# ================= USER DASHBOARD =================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    tasks = Task.query.filter_by(user_id=session["user_id"]).all()
    return render_template("dashboard.html", tasks=tasks, name=session["name"])

# ================= MARK TASK DONE =================

@app.route("/done/<int:id>")
def done(id):
    task = Task.query.get_or_404(id)

    if task.user_id != session.get("user_id"):
        flash("Unauthorized")
        return redirect("/dashboard")

    task.status = "Done"
    task.completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.session.commit()
    return redirect("/dashboard")

# ================= LOGOUT =================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ================= MAIN =================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
