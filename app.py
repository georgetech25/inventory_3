from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# Setup the secret key for session management
app.config['SECRET_KEY'] = os.urandom(24)  # Or a secure key string of your choice

# Database setup for PostgreSQL (Adjust credentials accordingly)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:lamis@localhost/Inventory'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the User model for SQLAlchemy
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # Role (admin or user)

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))

        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('signup'))

        # Hash the password with the default hashing method (pbkdf2:sha256)
        hashed_password = generate_password_hash(password)

        # Create a new user
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):  # Verify the hashed password
            # Store the user details in session
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role  # Can use 'admin' or 'user' role for permission checks
            flash('Login successful', 'success')
            return redirect(url_for('index'))  # Redirect to the home page or dashboard
        else:
            flash('Invalid credentials. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


# Index/Home Route
@app.route('/')
def index():
    if 'user_id' in session:
        return f'Hello, {session["username"]}! Your role: {session["role"]}'
    return redirect(url_for('login'))


# Admin Route (Automatically logs in with the admin credentials)
@app.route('/admin')
def admin():
    # Auto-login for admin (username: admin, password: Password@1)
    if 'user_id' not in session:
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            session['user_id'] = admin_user.id
            session['username'] = admin_user.username
            session['role'] = 'admin'
        else:
            flash('Admin user not found, please create the admin first.', 'danger')
            return redirect(url_for('signup'))
    
    return redirect(url_for('index'))


# To create the tables in your database, use the following:
# In Python shell, run: 
# from app import db
# db.create_all()




if __name__ == '__main__':
    app.run(debug=True)
