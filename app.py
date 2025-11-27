#!/usr/bin/env python3
"""
Telegram Username Search Web App (payments removed)
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import time
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# These modules must already exist in your project
from admin_data import admin_db
from searched_usernames import searched_username_manager

app = Flask(__name__)
# keep an env var option, fallback to a safe default
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'super-secret-key-change-this')

# Session config (keeps mobile compatibility like before)
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None',
    PERMANENT_SESSION_LIFETIME=1800
)

csrf = CSRFProtect(app)

CORS(app, resources={
    r'/*': {
        'origins': '*',
        'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'allow_headers': ['Content-Type', 'Authorization', 'X-Requested-With'],
        'supports_credentials': False
    }
})

app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Handle OPTIONS preflight for mobile clients
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        resp = app.make_response("")
        resp.headers.add("Access-Control-Allow-Origin", "*")
        resp.headers.add('Access-Control-Allow-Headers', "*")
        resp.headers.add('Access-Control-Allow-Methods', "*")
        return resp

# Admin credentials (unchanged)
ADMIN_CREDENTIALS = {
    'rxprime': os.environ.get('ADMIN_PASSWORD_HASH_1', generate_password_hash('rxprime'))
}


class TelegramUserSearch:
    """Demo search logic using admin_db demo usernames"""
    def __init__(self):
        pass

    def search_public_info(self, username):
        if username.startswith('@'):
            username = username[1:]
        demo_usernames = admin_db.get_usernames()
        username_lower = username.lower()
        for user_data in demo_usernames:
            if user_data.get('active') and user_data.get('username', '').lower() == username_lower:
                return {
                    "success": True,
                    "user_data": {
                        "username": user_data['username'],
                        "mobile_number": user_data.get('mobile_number'),
                        "mobile_details": user_data.get('mobile_details')
                    }
                }
        # not found
        return {
            "success": False,
            "error": "No details available in the database"
        }


searcher = TelegramUserSearch()


@app.route('/')
def home():
    if not session.get('authenticated'):
        return redirect(url_for('login_page'))
    return redirect(url_for('dashboard'))


@app.route('/login')
def login_page():
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
    # render login template
    resp = app.make_response(render_template('login.html'))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@app.route('/signup', methods=['POST'])
@csrf.exempt
def signup():
    try:
        data = request.get_json() or {}
        name = (data.get('name') or "").strip()
        if not name or len(name) < 2:
            return jsonify({'success': False, 'error': 'Please enter a valid name (at least 2 characters)'})
        new_user = admin_db.create_user(name)
        # set authenticated session and give BIG balance in session (for UI)
        session['authenticated'] = True
        session['user_hash'] = new_user['hash_code']
        session['user_name'] = new_user['name']
        session['user_balance'] = 999999
        return jsonify({
            'success': True,
            'message': 'Account created successfully!',
            'hash_code': new_user['hash_code'],
            'name': new_user['name']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Registration error occurred'})


@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    try:
        data = request.get_json() or {}
        hash_code = (data.get('hash_code') or "").strip()
        if not hash_code:
            return jsonify({'success': False, 'error': 'Please enter your hash code'})
        user = admin_db.get_user_by_hash(hash_code)
        if not user:
            return jsonify({'success': False, 'error': 'Invalid hash code. Please check and try again.'})
        # login success — set authenticated and VERY LARGE balance in session (UI only)
        session['authenticated'] = True
        session['user_hash'] = hash_code
        session['user_name'] = user.get('name')
        # ensure UI shows plenty of balance; internal DB left unchanged
        session['user_balance'] = 999999
        return jsonify({'success': True, 'message': f'Welcome back, {user.get("name")}!'})
    except Exception:
        return jsonify({'success': False, 'error': 'Authentication error occurred'})


@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        session.clear()
        return redirect(url_for('login_page'))
    # For display, prefer session balance (we set it to 999999 on login/signup)
    display_balance = session.get('user_balance', 999999)
    resp = app.make_response(render_template('index.html', balance=display_balance, user_name=session.get('user_name')))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/search', methods=['POST'])
@csrf.exempt
def search():
    """Free username search for all authenticated users — no balance checks, no deduction."""
    if not session.get('authenticated'):
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    try:
        data = request.get_json() or {}
        username = (data.get('username') or "").strip()
        if not username:
            return jsonify({'success': False, 'error': 'Please enter a username'})
        # perform the demo search (no charge)
        result = searcher.search_public_info(username)
        if result.get('success'):
            # return found data
            result['free'] = True
            return jsonify(result)
        else:
            # log searched username for admin review
            searched_username_manager.add_searched_username(username, session.get('user_hash'))
            custom_msg = admin_db.get_custom_message() if hasattr(admin_db, 'get_custom_message') else "No details found"
            return jsonify({'success': False, 'error': custom_msg})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500


# Removed deposit/UTR/payment endpoints entirely (per request).
# Keep health and admin routes (admin code mostly unchanged) so admin can still manage DB.

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "app": "Telegram Search Free", "version": "1.0"})


# ADMIN - keep existing admin endpoints (login, dashboard, API) so admin can manage demo data.
@app.route('/admin/login')
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
@csrf.exempt
def admin_login():
    try:
        data = request.get_json() or {}
        username = (data.get('username') or "").strip()
        password = (data.get('password') or "").strip()
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'})
        if username in ADMIN_CREDENTIALS and check_password_hash(ADMIN_CREDENTIALS[username], password):
            session['admin_authenticated'] = True
            session['admin_username'] = username
            return jsonify({'success': True, 'message': 'Admin access granted'})
        return jsonify({'success': False, 'error': 'Invalid admin credentials'})
    except Exception:
        return jsonify({'success': False, 'error': 'Authentication error occurred'})

@app.route('/admin/logout', methods=['POST'])
@csrf.exempt
def admin_logout():
    session.pop('admin_authenticated', None)
    session.pop('admin_username', None)
    return jsonify({'success': True})

# Keep admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_login_page'))
    from flask_wtf.csrf import generate_csrf
    return render_template('admin_dashboard.html', csrf_token=generate_csrf)


# Admin helper APIs (unchanged structure — admin_db functions used)
@app.route('/admin/api/statistics')
def admin_statistics():
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        stats = {
            'users': len(admin_db.get_users()),
            'usernames': len(admin_db.get_usernames())
        }
        # if admin_db has utrs still, include count, otherwise ignore
        try:
            stats['utrs'] = len(admin_db.get_utrs())
        except Exception:
            stats['utrs'] = 0
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/api/users')
def admin_get_users():
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(admin_db.get_users())


@app.route('/admin/api/usernames')
def admin_get_usernames():
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(admin_db.get_usernames())


# other admin CRUDs - keep as-is but minimal checks
@app.route('/admin/api/usernames', methods=['POST'])
@csrf.exempt
def admin_add_username():
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or {}
    username = (data.get('username') or "").strip()
    mobile_number = (data.get('mobile_number') or "").strip()
    mobile_details = (data.get('mobile_details') or "").strip()
    if not username or not mobile_number:
        return jsonify({'success': False, 'error': 'Username and mobile number required'})
    new_user = admin_db.add_username(username, mobile_number, mobile_details)
    return jsonify({'success': True, 'data': new_user})


# other admin endpoints (update/delete) can remain unchanged in your codebase; omitted here for brevity.

if __name__ == '__main__':
    # Run on 0.0.0.0 for container hosting
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
