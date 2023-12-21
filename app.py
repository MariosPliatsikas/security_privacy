from flask import Flask, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['MAIL_SERVER'] = 'your-mail-server'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email-username'
app.config['MAIL_PASSWORD'] = 'your-email-password'
    
db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    email_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(80), default='user')
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    return "Hello, World!"

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return 'No file part in the request.', 400

    file = request.files['file']

    if file.filename == '':
        return 'No selected file.', 400

    filename = secure_filename(file.filename)
    file.save(os.path.join('/path/to/save', filename))

    return 'File uploaded successfully.', 200

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        token = s.dumps(email, salt='email-confirm-salt')
        msg = Message('Confirm Email', sender='noreply@yourdomain.com', recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = 'Follow this link to confirm your email: {}'.format(link)
        mail.send(msg)
            
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm-email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except:
        return 'The confirmation link is invalid or has expired.'
    user = User.query.filter_by(email=email).first()
    user.email_verified = True
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('login'))  
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html') 
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    
@app.route('/home')
@login_required
def home():
    if current_user.role != 'admin':
        abort(403)
    return render_template('home.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        token = s.dumps(email, salt='password-reset-salt')
        msg = Message('Password Reset Request', sender='noreply@yourdomain.com', recipients=[email])
        link = url_for('reset_with_token', token=token, _external=True)
        msg.body = 'Follow this link to reset your password: {}'.format(link)
        mail.send(msg)
        return 'Email sent!'
    return render_template('reset_password.html')

@app.route('/reset-with-token/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return 'The password reset link is invalid or has expired.'
    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_with_token.html')

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

if __name__ == "__main__":
    app.run(debug=True)
