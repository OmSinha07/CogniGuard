# ============================================
# FILE: auth.py - Updated with TOTP & Fixed log_audit
# ============================================

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from models import db, User, AuditLog
from datetime import datetime, timedelta
import re
import pyotp 

auth_bp = Blueprint('auth', __name__)

# --- RESTORED LOG_AUDIT FUNCTION ---
def log_audit(action, user_id=None, details=None, success=True):
    """Log security audit event"""
    try:
        # Use the provided user_id, or fallback to current_user if authenticated
        effective_user_id = user_id
        if effective_user_id is None and current_user.is_authenticated:
            effective_user_id = current_user.id

        log = AuditLog(
            user_id=effective_user_id,
            action=action,
            details=details,
            ip_address=request.remote_addr,
            success=success
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        # Prevent audit failures from crashing the auth flow
        print(f"Audit log error: {e}")
# --- END RESTORED FUNCTION ---

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with TOTP secret generation"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        full_name = request.form.get('full_name', '').strip()

        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template('register.html')
        
        if not validate_email(email):
            flash('Invalid email address', 'error')
            return render_template('register.html')
        
        if password != password_confirm:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('register.html')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            log_audit('REGISTER_FAILED', details=f'Username exists: {username}', success=False)
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            log_audit('REGISTER_FAILED', details=f'Email exists: {email}', success=False)
            return render_template('register.html')

        try:
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                otp_secret=pyotp.random_base32() 
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Key generation (assuming crypto_utils_adaptive is available)
            from crypto_utils_adaptive import adaptive_crypto
            from key_storage import key_storage
            for sensitivity in ['LOW', 'MEDIUM', 'HIGH']:
                public_key, private_key, config_name = adaptive_crypto.generate_key_pair(sensitivity)
                key_storage.store_user_keys(public_key, private_key, username, sensitivity)

            log_audit('REGISTER_SUCCESS', user_id=user.id, details=f'New user: {username}')
            
            session['setup_2fa_user'] = username
            return redirect(url_for('auth.setup_2fa'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            log_audit('REGISTER_FAILED', details=str(e), success=False)
            return render_template('register.html')
    
    return render_template('register.html')

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    """Display QR code and then redirect to verification"""
    username = session.get('setup_2fa_user')
    if not username:
        return redirect(url_for('auth.login'))
    
    user = User.query.filter_by(username=username).first()
    
    if request.method == 'POST':
        # Once user clicks "I've scanned the code"
        session['pre_2fa_user_id'] = user.id
        session.pop('setup_2fa_user', None) # Clean up setup session
        return redirect(url_for('auth.verify_2fa'))
    
    return render_template('setup_2fa.html', secret=user.otp_secret, uri=user.get_totp_uri())

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Two-step login process with setup check"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()

        # 1. Validate User Existence
        if not user:
            flash('Invalid username or password', 'error')
            log_audit('LOGIN_FAILED', details=f'User not found: {username}', success=False)
            return render_template('login.html')
        
        # 2. Check Lock Status
        if user.is_account_locked():
            minutes_left = int((user.account_locked_until - datetime.utcnow()).total_seconds() / 60)
            flash(f'Account locked. Try again in {minutes_left} minutes.', 'error')
            log_audit('LOGIN_FAILED', user_id=user.id, details='Account locked', success=False)
            return render_template('login.html')
        
        # 3. Check Password
        if not user.check_password(password):
            user.increment_failed_attempts()
            flash('Invalid username or password', 'error')
            log_audit('LOGIN_FAILED', user_id=user.id, details='Wrong password', success=False)
            return render_template('login.html')
        
        # 4. Check Active Status
        if not user.is_active:
            flash('Account is deactivated. Contact support.', 'error')
            log_audit('LOGIN_FAILED', user_id=user.id, details='Account inactive', success=False)
            return render_template('login.html')

        # --- START OF 2FA LOGIC (REPLACING IMMEDIATE LOGIN) ---

        # Store the 'remember' preference in session for later
        session['remember_me'] = remember
        # Save the 'next' redirect if it exists
        session['next_url'] = request.args.get('next')

        # CHECK: If the user has a secret but has NEVER logged in, send to Setup (QR Code)
        if user.otp_secret and user.last_login is None:
            session['setup_2fa_user'] = user.username
            flash('Please scan this QR code to link your authenticator app.', 'info')
            return redirect(url_for('auth.setup_2fa'))
        
        # OTHERWISE: Proceed to standard 6-digit OTP verification
        session['pre_2fa_user_id'] = user.id
        return redirect(url_for('auth.verify_2fa'))
    
    return render_template('login.html')

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Second factor verification route"""
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    
    user = db.session.get(User, user_id)
    
    if request.method == 'POST':
        token = request.form.get('token')
        if user.verify_totp(token):
            login_user(user, remember=session.get('remember_me', False))
            user.update_last_login()
            
            session.pop('pre_2fa_user_id', None)
            session.pop('remember_me', None)
            
            log_audit('LOGIN_SUCCESS_2FA', user_id=user.id)
            flash(f'Welcome back, {user.full_name or user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code', 'error')
            log_audit('LOGIN_FAILED_2FA', user_id=user.id, details='Invalid OTP', success=False)
            
    return render_template('verify_2fa.html')

@auth_bp.route('/logout')
@login_required
def logout():
    log_audit('LOGOUT', user_id=current_user.id, details=f'User logged out: {current_user.username}')
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    total_files = current_user.files.count()
    total_size = sum(f.file_size for f in current_user.files) / (1024 * 1024)
    recent_logs = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('profile.html', user=current_user, total_files=total_files,
                         total_size=total_size, recent_logs=recent_logs)

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('change_password.html')
        
        try:
            current_user.set_password(new_password)
            db.session.commit()
            log_audit('PASSWORD_CHANGED', user_id=current_user.id)
            flash('Password changed successfully!', 'success')
            return redirect(url_for('auth.profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to change password: {str(e)}', 'error')
    
    return render_template('change_password.html')

@auth_bp.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password', '')
    if not current_user.check_password(password):
        flash('Incorrect password', 'error')
        return redirect(url_for('auth.profile'))
    
    try:
        username = current_user.username
        user_id = current_user.id
        
        import os
        for file in current_user.files:
            filepath = os.path.join('encrypted_uploads', file.filename)
            if os.path.exists(filepath):
                os.remove(filepath)
        
        log_audit('ACCOUNT_DELETED', user_id=user_id, details=f'User deleted account: {username}')
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Your account has been deleted.', 'info')
        return redirect(url_for('auth.register'))
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete account: {str(e)}', 'error')
        return redirect(url_for('auth.profile'))