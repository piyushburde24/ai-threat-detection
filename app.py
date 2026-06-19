import os
import logging
import sqlite3
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

DB_FILE = "users.db"

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

# --- Isolated Security Logger Setup ---
security_logger = logging.getLogger("security_pipeline")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

file_handler = logging.FileHandler('app.log')
security_formatter = logging.Formatter('%(asctime)s [%(levelname)s] IP: %(client_ip)s - User: %(user)s - Event: %(message)s')
file_handler.setFormatter(security_formatter)
security_logger.addHandler(file_handler)

# --- Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    admin_key = PasswordField('Admin Registration Key (Optional)') # Added field for restriction
    submit = SubmitField('Register')

def log_security_event(level, username, message):
    client_ip = request.remote_addr or "127.0.0.1"
    extra_data = {'client_ip': client_ip, 'user': username or "Anonymous"}
    if level == "INFO":
        security_logger.info(message, extra=extra_data)
    elif level == "WARNING":
        security_logger.warning(message, extra=extra_data)

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()

        if row and bcrypt.check_password_hash(row[0], password):
            log_security_event("INFO", username, "Successful Login Attempt")
            return redirect(url_for('dashboard'))
        else:
            log_security_event("WARNING", username, "Failed Login Attempt - Invalid Credentials")
            flash('Invalid Username or Password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        admin_key_input = form.admin_key.data
        
        # Define the system's secret admin registration token via Environment Variable
        SECRET_REG_KEY = os.getenv("ADMIN_REGISTRATION_KEY", "SuperSecretKey999!")

        # RESTRICTION LOGIC: If trying to register as admin, validate the key
        if username.lower() == "admin":
            if admin_key_input != SECRET_REG_KEY:
                log_security_event("WARNING", username, "Unauthorized Registration Attempt - Invalid Secret Key")
                flash('Unauthorized! A valid Admin Registration Key is required to create an admin account.', 'danger')
                return render_template('register.html', form=form)

        # Secure Password Hashing via Bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
            log_security_event("INFO", username, "User Registered Successfully")
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            log_security_event("WARNING", username, "Registration Failed - Username Already Exists")
            flash('Username already exists. Choose a different one.', 'danger')

    return render_template('register.html', form=form)

@app.route('/dashboard')
def dashboard():
    return "<h1>Welcome to the Secure Admin Dashboard!</h1>"

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
