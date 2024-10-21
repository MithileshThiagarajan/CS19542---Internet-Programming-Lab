from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_default_secret_key')  # Use env variable for secret key

# MongoDB connection details
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/rec')
mongo = PyMongo(app)

@app.route('/')
def index():
    print("Index route called")  # Debug print
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate email format
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address.')
            return redirect(url_for('index'))

        # Check if user already exists
        user = mongo.db.users.find_one({'email': email})
        if user:
            flash('Email address already exists.')
            return redirect(url_for('index'))

        # Hash the password before storing it in the database
        hashed_password = generate_password_hash(password, method='sha256')

        # Insert user data into MongoDB
        try:
            mongo.db.users.insert_one({
                'name': name,
                'email': email,
                'password': hashed_password
            })
            flash('Account created successfully! Please log in.')
        except Exception as e:
            flash('An error occurred while creating your account. Please try again.')
            print(f'Error: {e}')  # Debug print

        return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the user exists
        user = mongo.db.users.find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            session['user'] = user['name']  # Store user info in session
            flash('Login successful!')
            return redirect(url_for('db'))  # Redirect to db.html
        else:
            flash('Invalid email or password.')
            return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/db')
def db():
    if 'user' in session:
        return render_template('db.html', user=session['user']) 
    else:
        flash('You need to log in first.')
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user', None)  
    flash('You have been logged out.')
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
