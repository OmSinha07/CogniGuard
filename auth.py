# ============================================
# FILE: auth.py - Authentication Routes
# ============================================

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from models import db, User, AuditLog
from datetime import datetime, timedelta
import re

auth_bp = Blueprint('auth', __name__)

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

def log_audit(action, user_id=None, details=None, success=True):
    """Log security audit event"""
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=request.remote_addr,
            success=success
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Audit log error: {e}")

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
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
        
        # Create user
        try:
            user = User(
                username=username,
                email=email,
                full_name=full_name
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Generate encryption keys for the user
            from crypto_utils_adaptive import adaptive_crypto
            from key_storage import key_storage
            
            for sensitivity in ['LOW', 'MEDIUM', 'HIGH']:
                public_key, private_key, config_name = adaptive_crypto.generate_key_pair(sensitivity)
                key_storage.store_user_keys(public_key, private_key, username, sensitivity)
            
            log_audit('REGISTER_SUCCESS', user_id=user.id, details=f'New user: {username}')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            log_audit('REGISTER_FAILED', details=str(e), success=False)
            return render_template('register.html')
    
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Invalid username or password', 'error')
            log_audit('LOGIN_FAILED', details=f'User not found: {username}', success=False)
            return render_template('login.html')
        
        # Check if account is locked
        if user.is_account_locked():
            minutes_left = int((user.account_locked_until - datetime.utcnow()).total_seconds() / 60)
            flash(f'Account locked. Try again in {minutes_left} minutes.', 'error')
            log_audit('LOGIN_FAILED', user_id=user.id, details='Account locked', success=False)
            return render_template('login.html')
        
        # Check password
        if not user.check_password(password):
            user.increment_failed_attempts()
            flash('Invalid username or password', 'error')
            log_audit('LOGIN_FAILED', user_id=user.id, details='Wrong password', success=False)
            return render_template('login.html')
        
        # Check if account is active
        if not user.is_active:
            flash('Account is deactivated. Contact support.', 'error')
            log_audit('LOGIN_FAILED', user_id=user.id, details='Account inactive', success=False)
            return render_template('login.html')
        
        # Successful login
        login_user(user, remember=remember)
        user.update_last_login()
        log_audit('LOGIN_SUCCESS', user_id=user.id, details=f'User logged in: {username}')
        
        flash(f'Welcome back, {user.full_name or user.username}!', 'success')
        
        # Redirect to next page or home
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('index'))
    
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    log_audit('LOGOUT', user_id=current_user.id, details=f'User logged out: {current_user.username}')
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    # Get user statistics
    total_files = current_user.files.count()
    total_size = sum(f.file_size for f in current_user.files) / (1024 * 1024)  # MB
    
    # Get recent activity
    recent_logs = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('profile.html', 
                         user=current_user, 
                         total_files=total_files,
                         total_size=total_size,
                         recent_logs=recent_logs)

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Verify current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('change_password.html')
        
        # Update password
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
    """Delete user account"""
    password = request.form.get('password', '')
    
    if not current_user.check_password(password):
        flash('Incorrect password', 'error')
        return redirect(url_for('auth.profile'))
    
    try:
        username = current_user.username
        user_id = current_user.id
        
        # Delete user files
        import os
        for file in current_user.files:
            filepath = os.path.join('encrypted_uploads', file.filename)
            if os.path.exists(filepath):
                os.remove(filepath)
        
        # Log before deletion
        log_audit('ACCOUNT_DELETED', user_id=user_id, details=f'User deleted account: {username}')
        
        # Delete user
        db.session.delete(current_user)
        db.session.commit()
        
        logout_user()
        flash('Your account has been deleted.', 'info')
        return redirect(url_for('auth.register'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete account: {str(e)}', 'error')
        return redirect(url_for('auth.profile'))