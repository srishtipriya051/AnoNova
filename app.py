from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import random
import string

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key in production

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS available_userids
                 (userid TEXT UNIQUE NOT NULL)''')
    conn.commit()
    conn.close()

# Initialize the database when the app starts
init_db()

def generate_userid():
    # Format: TT + 6 digits (e.g., TT123456)
    while True:
        numbers = ''.join(random.choices(string.digits, k=6))
        userid = f"TT{numbers}"
        
        # Check if userid is already in use
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        exists = c.execute('SELECT 1 FROM users WHERE username = ?', (userid,)).fetchone()
        if not exists:
            # Store in available_userids table
            try:
                c.execute('INSERT INTO available_userids (userid) VALUES (?)', (userid,))
                conn.commit()
                conn.close()
                return userid
            except sqlite3.IntegrityError:
                conn.close()
                continue
        conn.close()

def get_next_userid():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Try to get an existing available userid
    userid = c.execute('SELECT userid FROM available_userids LIMIT 1').fetchone()
    
    if userid:
        # Remove it from available userids
        c.execute('DELETE FROM available_userids WHERE userid = ?', (userid[0],))
        conn.commit()
        conn.close()
        return userid[0]
    
    conn.close()
    # If no userid is available, generate a new one
    return generate_userid()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        user = c.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid UserID or password.')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                     (username, password_hash))
            conn.commit()
            conn.close()
            flash(f'Account created successfully! Your UserID is {username}')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('An error occurred. Please try again.')
            return redirect(url_for('signup'))
    
    # Generate a new userid for the signup form
    new_userid = get_next_userid()
    return render_template('create_account.html', userid=new_userid)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) 