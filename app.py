from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_mail import Mail, Message
import random
from dotenv import load_dotenv
import os
import bcrypt

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Flask-Mail Configuration (using environment variables)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# App configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
mail = Mail(app)  # Initialize Flask-Mail
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy data for random job generation
JOB_TITLES = ["Software Engineer", "Data Analyst", "Product Manager", "UX Designer", "DevOps Engineer"]
COMPANY_NAMES = ["TechCorp", "DataWorks", "Innovate Inc", "DesignHub", "CloudNet"]
LOCATIONS = ["New York", "San Francisco", "Chicago", "Austin", "Seattle"]

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    skills = db.Column(db.String(200))
    job_role = db.Column(db.String(100))

class JobVacancy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_title = db.Column(db.String(100), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('job_vacancy.id'), nullable=False)
    status = db.Column(db.String(20), default='Saved')
    is_saved = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref=db.backref('applications', lazy=True))
    job_vacancy = db.relationship('JobVacancy', backref=db.backref('applications', lazy=True))

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField('Signup')

class UserDataForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=100)])
    age = StringField('Age', validators=[InputRequired()])
    gender = StringField('Gender', validators=[InputRequired(), Length(max=10)])
    skills = StringField('Skills', validators=[InputRequired(), Length(max=200)])
    job_role = StringField('Job Role', validators=[InputRequired(), Length(max=100)])
    submit = SubmitField('Submit')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('signup'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered')
            return redirect(url_for('login'))
        
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['email'] = form.email.data
        session['password'] = hashed_password.decode('utf-8')
        
        try:
            send_otp_email(form.email.data, otp)
            flash('OTP has been sent to your email. Please verify.')
        except Exception as e:
            flash(f"Failed to send OTP. Please try again later. Error: {str(e)}")
            return redirect(url_for('signup'))
        
        return redirect(url_for('verify_otp'))
    
    return render_template('signup.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if entered_otp == session.get('otp'):
            new_user = User(email=session['email'], password=session['password'])
            db.session.add(new_user)
            db.session.commit()
            
            session.pop('otp', None)
            session.pop('email', None)
            session.pop('password', None)
            
            login_user(new_user)
            flash('Account created successfully! Please complete your profile.')
            return redirect(url_for('user_data'))
        else:
            flash('Invalid OTP')
    
    return render_template('OTP-Verification.html')

@app.route('/user_data', methods=['GET', 'POST'])
@login_required
def user_data():
    form = UserDataForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.age = int(form.age.data)
        current_user.gender = form.gender.data
        current_user.skills = form.skills.data
        current_user.job_role = form.job_role.data
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('User.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # Generate random job vacancies
    num_random_jobs = 5  # Number of random jobs to generate
    for _ in range(num_random_jobs):
        job_title = random.choice(JOB_TITLES)
        company_name = random.choice(COMPANY_NAMES)
        location = random.choice(LOCATIONS)
        
        # Check if the job already exists
        existing_job = JobVacancy.query.filter_by(job_title=job_title, company_name=company_name, location=location).first()
        if not existing_job:
            new_job = JobVacancy(job_title=job_title, company_name=company_name, location=location)
            db.session.add(new_job)
    db.session.commit()

    # Fetch all job vacancies
    job_vacancies = JobVacancy.query.all()
    return render_template('Dashboard.html', user=current_user, job_vacancies=job_vacancies)

@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if current_user.id != user_id:
        return {'success': False, 'message': 'Unauthorized'}, 403
    data = request.get_json()
    user = User.query.get(user_id)
    if not user:
        return {'success': False, 'message': 'User not found'}, 404
    user.name = data.get('name')
    user.age = int(data.get('age'))
    user.gender = data.get('gender')
    user.skills = data.get('skills')
    user.job_role = data.get('job_role')
    db.session.commit()
    return {'success': True, 'message': 'Profile updated successfully'}

@app.route('/job_vacancies')
@login_required
def job_vacancies():
    job_vacancies = JobVacancy.query.all()
    job_applications = Application.query.filter_by(user_id=current_user.id).all()
    return render_template('job_vacancies.html', job_vacancies=job_vacancies, job_applications=job_applications)

@app.route('/update_status', methods=['POST'])
@login_required
def update_status():
    job_id = request.form.get('job_id')
    application_id = request.form.get('application_id')
    status = request.form.get('status')
    if job_id:
        application = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()
        if not application:
            application = Application(user_id=current_user.id, job_id=job_id, status='Saved')
            db.session.add(application)
        else:
            application.is_saved = not application.is_saved
        db.session.commit()
        return redirect(url_for('job_vacancies'))
    if application_id:
        application = Application.query.get(application_id)
        if application and application.user_id == current_user.id:
            if status in ["Saved", "Applied", "Offered", "Rejected"]:
                application.status = status
                db.session.commit()
        job_applications = Application.query.filter_by(user_id=current_user.id).all()
        return render_template('my_applications.html', job_applications=job_applications)
        #return redirect(url_for('my_applications'))
    return {'success': False, 'message': 'Invalid request'}, 400

@app.route('/my_applications')
@login_required
def my_applications():
    job_applications = Application.query.filter_by(user_id=current_user.id, is_saved=True).all()
    return render_template('my_applications.html', job_applications=job_applications, user=current_user)

@app.route('/withdraw_application/<int:application_id>', methods=['POST'])
@login_required
def withdraw_application(application_id):
    # Fetch the application by ID
    application = Application.query.get(application_id)
    
    # Check if the application exists and belongs to the current user
    if not application or application.user_id != current_user.id:
        flash('Invalid application or unauthorized access.')
        return redirect(url_for('my_applications'))
    
    # Delete the application
    db.session.delete(application)
    db.session.commit()
    
    job_applications = Application.query.filter_by(user_id=current_user.id).all()
    
    flash('Application withdrawn successfully.')
    return render_template('my_applications.html', job_applications=job_applications)
    #return redirect(url_for('my_applications'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Helper Function to Send OTP via Gmail with Error Handling
def send_otp_email(recipient_email, otp):
    try:
        msg = Message("Your OTP for Verification", recipients=[recipient_email])
        msg.body = f"Your OTP is: {otp}. Please do not share this with anyone."
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        raise e

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)