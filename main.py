from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()
logged_in = False


@app.route('/')
def home():
    return render_template("index.html", logged_in=logged_in)


@app.route('/register', methods=["POST", "GET"])
def register():
    error = None
    if request.method == "POST":
        new_user = User()
        new_user.name = request.form["name"]
        new_user.email = request.form["email"]
        # print(User.query.filter_by(email=new_user.email))
        user_in_db = User.query.filter_by(email=new_user.email).first()
        if user_in_db:
            error = "You already have signed up with that email, log in instead."
            return render_template("login.html", error=error)
        new_user.password = generate_password_hash(
            password=request.form["password"],
            method="pbkdf2:sha256",
            salt_length=8
            )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        global logged_in
        logged_in = True
        return redirect(url_for("secrets", name=new_user.name))
    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    error = None
    if request.method == "POST":
        email_entered = request.form["email"]
        password_entered = request.form["password"]
        user_in_db = User.query.filter_by(email=email_entered).first()
        if user_in_db:
            hashed_password = user_in_db.password
            if check_password_hash(pwhash=hashed_password, password=password_entered):
                login_user(user_in_db)
                global logged_in
                logged_in = True
                flash('Logged in successfully.')
                return redirect(url_for("secrets", name=user_in_db.name))
            else:
                error = 'Invalid credentials, try again.'
        else:
            error = 'User with that email does not exist.'
    return render_template("login.html", error=error)


@app.route('/secrets/<name>')
@login_required
def secrets(name):
    return render_template("secrets.html", name=name, logged_in=logged_in)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    global logged_in
    logged_in = False
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory="static/files",
                               filename="cheat_sheet.pdf")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


if __name__ == "__main__":
    app.run(debug=True)
