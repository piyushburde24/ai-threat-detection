import os
import logging
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
csrf = CSRFProtect(app)

security_logger = logging.getLogger("security_pipeline")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

file_handler = logging.FileHandler('app.log')
security_formatter = logging.Formatter('%(asctime)s [%(levelname)s] IP: %(client_ip)s - User: %(user)s - Event: %(message)s')
file_handler.setFormatter(security_formatter)
security_logger.addHandler(file_handler)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def log_security_event(level, username, message):
    client_ip = request.remote_addr or "127.0.0.1"
    extra_data = {'client_ip': client_ip, 'user': username or "Anonymous"}
    if level == "INFO":
        security_logger.info(message, extra=extra_data)
    elif level == "WARNING":
        security_logger.warning(message, extra=extra_data)

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        if username == "admin" and password == "SuperSecurePassword123!":
            log_security_event("INFO", username, "Successful Login Attempt")
            return redirect(url_for('dashboard'))
        else:
            log_security_event("WARNING", username, "Failed Login Attempt - Invalid Credentials")
            flash('Invalid Username or Password', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    return "<h1>Welcome to the Secure Admin Dashboard!</h1>"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
