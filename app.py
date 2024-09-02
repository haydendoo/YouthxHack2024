from flask import Flask, render_template, g, session, redirect, url_for
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv
import os
import sqlite3
import smtplib, ssl
from itsdangerous import URLSafeTimedSerializer
import re

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["VERIFY_SECRET"] = os.getenv("VERIFY_SECRET")
app.config["VERIFY_SALT"] = os.getenv("VERIFY_SALT")

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

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/signup')
def signup():
    return render_template("signup.html")

@app.route('/forgetpassword')
def forgetpassword():
    return render_template("forgetpassword.html")

@app.route('/app')
def app():
    return render_template('app.html')

@app.route('/app/settings')
def settings():
    return render_template('settings.html')

# APIs
@app.route('/verify/url', methods=["POST"])
def verify_url():
    pass

@app.route('/verify/emailsms', methods=["POST"])
def verify_emailsms():
    pass

@app.route('/report', methods=["POST"])
def report():
    pass

@app.route('/report/approve/<id>', methods=['POST'])
def report_approve(id):
    pass

@app.errorhandler(HTTPException)
def error_page(error):
    code = error.code if isinstance(error, HTTPException) else 500
    return render_template('error.html', code=code), code

@app.route('/logout')
def logout():
    if 'authorization' in session:
        session.pop('authorization')

    return redirect(url_for('app'))

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

def confirm_verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config["VERIFY_SECRET"])
    try:
        email = serializer.loads(token, salt=app.config["VERIFY_SALT"], max_age=expiration)
        return email
    except Exception:
        return False

if __name__ == "__main__":
    app.run(debug=True)