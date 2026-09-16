from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'RVP_LOGIN_SECRET_KEY_2026'

# Database file (local storage)
DATA_FILE = 'rvp_users.json'

def load_users():
    """Load users from JSON file"""
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Save users to JSON file"""
    with open(DATA_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def get_user_by_username(username):
    """Find user by username"""
    users = load_users()
    return users.get(username)

def get_user_by_email(email):
    """Find user by email"""
    users = load_users()
    for username, user_data in users.items():
        if user_data.get('email') == email:
            return username, user_data
    return None, None

# ============ ROUTES ============

@app.route('/')
def index():
    """Home page - redirect based on login status"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Sign Up Route"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        # Validation
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields required!'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be 6+ characters!'}), 400
        
        users = load_users()
        
        # Check if username exists
        if username in users:
            return jsonify({'success': False, 'message': 'Username already taken!'}), 400
        
        # Check if email exists
        existing_username, _ = get_user_by_email(email)
        if existing_username:
            return jsonify({'success': False, 'message': 'Email already registered!'}), 400
        
        # Create new user
        users[username] = {
            'email': email,
            'password': generate_password_hash(password),
            'created_at': datetime.now().isoformat(),
            'is_owner': username == 'Sher' or username == 'Raad'  # Owner check
        }
        
        save_users(users)
        return jsonify({'success': True, 'message': 'Account created! Now sign in.'}), 201
    
    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    """Sign In Route"""
    if request.method == 'POST':
        data = request.get_json()
        login_input = data.get('login', '').strip()  # username or email
        password = data.get('password', '').strip()
        
        if not login_input or not password:
            return jsonify({'success': False, 'message': 'Login and password required!'}), 400
        
        # Check by username first
        user_data = get_user_by_username(login_input)
        username = login_input
        
        # If not found by username, check by email
        if not user_data:
            username, user_data = get_user_by_email(login_input)
        
        # Verify credentials
        if user_data and check_password_hash(user_data['password'], password):
            session['username'] = username
            session['is_owner'] = user_data.get('is_owner', False)
            return jsonify({'success': True, 'message': 'Logged in!', 'redirect': url_for('dashboard')}), 200
        
        return jsonify({'success': False, 'message': 'Invalid login or password!'}), 401
    
    return render_template('signin.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard - only for logged in users"""
    if 'username' not in session:
        return redirect(url_for('signin'))
    
    user_data = get_user_by_username(session['username'])
    return render_template('dashboard.html', username=session['username'], is_owner=session.get('is_owner', False), email=user_data.get('email'))

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('signin'))

@app.route('/api/user-info')
def user_info():
    """Get current user info"""
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user_data = get_user_by_username(session['username'])
    return jsonify({
        'username': session['username'],
        'email': user_data.get('email'),
        'is_owner': session.get('is_owner', False),
        'created_at': user_data.get('created_at')
    }), 200

@app.route('/api/admin/users')
def admin_users():
    """Admin only - get all users"""
    if 'username' not in session or not session.get('is_owner'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = load_users()
    user_list = []
    for username, data in users.items():
        user_list.append({
            'username': username,
            'email': data.get('email'),
            'created_at': data.get('created_at'),
            'is_owner': data.get('is_owner', False)
        })
    
    return jsonify({'users': user_list}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
