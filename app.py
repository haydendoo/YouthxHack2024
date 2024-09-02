from flask import Flask, render_template, g, session, redirect, url_for, request, jsonify, abort
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv
import os
import sqlite3
import smtplib, ssl
from itsdangerous import URLSafeTimedSerializer
from email.message import EmailMessage
import re
from argon2 import PasswordHasher
import secrets
import datetime

from models.emailsms_phish import is_emailsms_phishing

load_dotenv()

app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["VERIFY_SECRET"] = os.getenv("VERIFY_SECRET")
app.config["VERIFY_SALT"] = os.getenv("VERIFY_SALT")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)

NOREPLY_EMAIL = "noreply.haydenhow@gmail.com"
DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form.get("email").strip()
        password = request.form.get("password")

        if email == None or password == None:
            return render_template("login.html", msg="Make sure to fill out all fields")

        with app.app_context():
            db = get_db()
            cursor = db.cursor()

            user = cursor.execute("SELECT * FROM users WHERE email=?", (email, )).fetchone()
            if not user:
                return render_template("login.html", msg="Incorrect email and password combination")

            if not user[3]:
                return render_template("login.html", msg="This account has not been verified yet")

            try:
                ph = PasswordHasher()
                if not ph.verify(user[2], password):
                    return render_template("login.html", msg="Incorrect email and password combination")
            except:
                return render_template("login.html", msg="Incorrect email and password combination")

            session['authorization'] = {'user_id': user[0], 'token': user[4]}
            session.permanent = True

        return redirect(url_for('dashboard'))

    return render_template("login.html")

@app.route('/signup', methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        email = request.form.get("email").strip()
        password = request.form.get("password")
        confirm = request.form.get("confirmPassword")

        msgs = []
        if email == None or password == None or confirm == None:
            msgs.append("You must fill out all fields")

        if not valid_email(email):
            msgs.append("Email is invalid")

        if password != confirm:
            msgs.append("Passwords do not match")

        if len(password) < 8:
            msgs.append("Password must contain atleast 8 characters")

        ph = PasswordHasher()
        hash = ph.hash(password)

        with app.app_context():
            db = get_db()
            cursor = db.cursor()

            email_exists = cursor.execute("SELECT * FROM users WHERE email=?", (email, )).fetchone()
            if email_exists:
                msgs.append("This email already created an account")

            if len(msgs) != 0:
                return render_template("signup.html", msgs=msgs)

            cursor.execute(
            """
            INSERT INTO users(email, password, verified, token)
            VALUES (?, ?, 0, ?)
            """
            , (email, hash, secrets.token_urlsafe(64)))
            db.commit()

            verification_link = f"http://127.0.0.1:5000/verify_email/{ generate_verify_token(email, expirtion) }"

        send_email(email, 'Verification for your account', 
                    f'''
                    Hi {email}!\n
                    Thank you for signing up. If you were not the one who signed up, you can ignore this and the account will not be verified.\n
                    Click on this link to verify your account now.\n
                    {verification_link}
                    '''
                   )

        return render_template("signup.html", final="Your account has been created. An email will be sent to verify it.")
    return render_template("signup.html")

@app.route('/forgetpassword', methods=["POST", "GET"])
def forgetpassword():
    if request.method == "POST":
        email = request.form.get("email")
        if email == None:
            return render_template("forgetpassword.html", exists=False)

        with app.app_context():
            db = get_db()
            cursor = db.cursor()

            email_exists = cursor.execute("SELECT * FROM users WHERE email=?", (email, )).fetchone()
            if not email_exists:
                return render_template("forgetpassword.html", not_exist=True)

            reset_link = f"http://127.0.0.1:5000/reset/{ generate_verify_token(email) }"

        send_email(email, 'Password reset for your account', 
                    f'''
                    Hi {email}!\n
                    Click on this link to reset your password now. This link will expire in 1 hour.\n
                    {reset_link}
                    If you were not the one who did this, you can ignore this and the password will not be resetted.\n
                    '''
                   )


            
    return render_template("forgetpassword.html")

@app.route('/app')
def dashboard():
    if not logged_in():
        abort(401)

    return render_template('app.html')

@app.route('/app/settings', methods=["POST", "GET"])
def settings():
    if not logged_in():
        abort(401)

    if request.method == "POST":
        current = request.form.get("current-password", "")
        password = request.form.get("new-password", "")
        confirm = request.form.get("confirm-password", "")

        if password != confirm:
            return render_template('settings.html', not_match=True)

        if len(password) < 8:
            return render_template('settings.html', too_small=True)

        with app.app_context():
            db = get_db()
            cursor = db.cursor()
            user = cursor.execute("SELECT * FROM users WHERE id=?", (get_userid(),)).fetchone()
            ph = PasswordHasher()
            print(current, user[2])
            try:
                ph.verify(user[2], current)
            except:
                return render_template('settings.html', wrong=True)

            cursor.execute("UPDATE users SET password=? WHERE id=?", (ph.hash(password), get_userid()))
            db.commit()
            return render_template('settings.html', success=True)

    return render_template('settings.html')

# APIs
@app.route('/verify/url', methods=["POST"])
def verify_url():
    if not logged_in():
        abort(401)

    pass

@app.route('/verify/emailsms', methods=["POST"])
def verify_emailsms():
    if not logged_in():
        abort(401)

    msg = request.data.decode('utf-8')
    phish = is_emailsms_phishing(msg)
    return jsonify({'phish': str(phish)})

@app.route('/report', methods=["POST"])
def report():
    if not logged_in():
        abort(401)

    pass

@app.route('/report/approve/<id>', methods=['POST'])
def report_approve(id):
    if not logged_in():
        abort(401)

    pass

@app.errorhandler(HTTPException)
def error_page(error):
    code = error.code if isinstance(error, HTTPException) else 500
    return render_template('error.html', code=code), code

@app.route('/logout')
def logout():
    if 'authorization' in session:
        session.pop('authorization')

    return redirect(url_for('index'))

@app.route('/verify_email/<token>')
def verify(token):
    # Verify account
    with app.app_context():
        email = confirm_verify_token(token)
        if email == False:
            abort(404)

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email, ))
        user = cursor.fetchone()

        if not user:
            abort(404)

        cursor.execute("UPDATE users SET verified=1 WHERE email=?", (email,))

        db.commit()

    return render_template('verify.html')

@app.route('/reset/<token>', methods=["POST", "GET"])
def reset(token):
    email = confirm_verify_token(token)
    if email == False:
        abort(404)

    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirmPassword")
        if password == None:
            return render_template('reset.html', msg="Password must contain atleast 8 characters")

        if password != confirm:
            return render_template('reset.html', msg="Passwords do not match")

        with app.app_context():
            db = get_db()
            cursor = db.cursor()

            cursor.execute("SELECT * FROM users WHERE email=?", (email, ))
            user = cursor.fetchone()
            if not user:
                abort(404)

            ph = PasswordHasher()
            hash = ph.hash(password)
            cursor.execute("UPDATE users SET password=? WHERE email=?", (hash, email))
            db.commit()
            return redirect(url_for('login'))

    return render_template('reset.html')

# Utils
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

def send_email(email, subject, text):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = NOREPLY_EMAIL
    msg['To'] = email
    msg['X-Priority'] = '2'

    msg.set_content(text)
    
    context = ssl.create_default_context()
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls(context=context)
        server.login(NOREPLY_EMAIL, EMAIL_PASSWORD)
        server.sendmail(NOREPLY_EMAIL, email, msg.as_string())

def valid_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    return True if re.fullmatch(regex, email) else False

def generate_verify_token(email):
    serializer = URLSafeTimedSerializer(app.config['VERIFY_SECRET'])
    return serializer.dumps(email, salt=app.config['VERIFY_SALT'])

def confirm_verify_token(token, expire=False):
    serializer = URLSafeTimedSerializer(app.config["VERIFY_SECRET"])
    try:
        if expire:
            email = serializer.loads(token, salt=app.config["VERIFY_SALT"], max_age=3600)
        else:
            email = serializer.loads(token, salt=app.config["VERIFY_SALT"])
        return email
    except Exception:
        return False

def logged_in():
    if 'authorization' not in session:
        return False
    
    id = session['authorization']['user_id']
    token = session['authorization']['token']

    with app.app_context():
        cursor = get_db().cursor()
        user = cursor.execute("SELECT * FROM users WHERE id=?", (id, )).fetchone()
        if user[4] == token:
            return True

    return False

def get_userid():
    if 'authorization' not in session:
        return None

    return session['authorization']['user_id']

if __name__ == "__main__":
    app.run(debug=True)