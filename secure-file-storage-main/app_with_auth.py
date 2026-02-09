# ============================================
# FILE: app_with_auth.py - Main Application with Authentication
# ============================================

import os
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from flask_login import LoginManager, login_required, current_user
from werkzeug.utils import secure_filename
import tempfile
import time
from datetime import timedelta
import psutil  # For resource metrics
import csv # <<< ADDED
from datetime import datetime # <<< ADDED

# Import models and blueprints
from models import db, User, EncryptedFile, AuditLog
from auth import auth_bp

# Import existing modules
from ml_classifier import ml_classifier
from crypto_utils_adaptive import adaptive_crypto
from key_storage import key_storage

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///secure_storage.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

UPLOAD_FOLDER = 'encrypted_uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip'}

# --- Performance Log Files --- # <<< ADDED
UPLOAD_PERFORMANCE_CSV = 'upload_performance_metrics.csv'
DOWNLOAD_PERFORMANCE_CSV = 'download_performance_metrics.csv'
# --- END ADDED --- #

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    # --- UPDATED CODE ---
    # Changed from User.query.get() to db.session.get() to fix LegacyAPIWarning
    return db.session.get(User, int(user_id))
    # --- END UPDATE ---

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_audit(action, details=None, success=True):
    """Helper to log audit events"""
    try:
        log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            details=details,
            ip_address=request.remote_addr,
            success=success
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass # Keep the original silent pass

# --- Helper function to log performance metrics --- # <<< ADDED
def write_metrics_to_csv(csv_file, metrics_dict, fieldnames):
    """Helper to append performance metrics to a CSV file."""
    try:
        file_exists = os.path.exists(csv_file)
        
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(metrics_dict)
            
    except Exception as e:
        # Don't crash the app if logging fails, just print to console
        print(f"Error writing to performance CSV {csv_file}: {e}")
        pass # Keep the original silent pass
# --- END ADDED --- #


@app.route('/')
@login_required
def index():
    """Main page - file dashboard"""
    # Get current user's files
    user_files = EncryptedFile.query.filter_by(user_id=current_user.id)\
        .order_by(EncryptedFile.uploaded_at.desc()).all()
    
    # Convert to dictionary format for template
    files_dict = {}
    for file in user_files:
        files_dict[str(file.id)] = {
            'filename': file.filename,
            'original_filename': file.original_filename,
            'file_size': file.file_size,
            'sensitivity': file.sensitivity,
            'ml_confidence': file.ml_confidence,
            'entropy': file.entropy,
            'crypto_config': file.crypto_config,
            'uploaded_at': file.uploaded_at.isoformat(),
            'encrypted_aes_key': file.encrypted_aes_key
        }
    
    return render_template('index_ml_adaptive.html', 
                         files=files_dict, 
                         user_id=current_user.username)

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    # Get user's file statistics
    user_files = EncryptedFile.query.filter_by(user_id=current_user.id).all()
    
    # Calculate stats
    total_files = len(user_files)
    total_storage = sum(f.file_size for f in user_files)
    
    # Sensitivity breakdown
    sensitivity_counts = {
        'LOW': sum(1 for f in user_files if f.sensitivity == 'LOW'),
        'MEDIUM': sum(1 for f in user_files if f.sensitivity == 'MEDIUM'),
        'HIGH': sum(1 for f in user_files if f.sensitivity == 'HIGH')
    }
    
    # Recent activity (last 10 audit logs)
    # This might fail silently if the audit_log table doesn't exist
    try:
        recent_activity = AuditLog.query.filter_by(user_id=current_user.id)\
            .order_by(AuditLog.timestamp.desc())\
            .limit(10).all()
    except Exception as e:
        print(f"Warning: Could not fetch recent activity - {e}")
        recent_activity = [] # Show empty list if query fails

    # Convert storage to human readable
    def format_bytes(bytes_val):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} TB"
    
    return render_template('profile.html',
                         user=current_user,
                         total_files=total_files,
                         total_storage=format_bytes(total_storage),
                         sensitivity_counts=sensitivity_counts,
                         recent_activity=recent_activity)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle ML-adaptive encrypted file upload"""
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '' or not (file and allowed_file(file.filename)):
        flash('Invalid file', 'error')
        return redirect(url_for('index'))
    
    try:
        start_time = time.time()
        
        # --- ADDED FOR METRICS ---
        process = psutil.Process(os.getpid())
        cpu_start = process.cpu_percent(interval=None)
        mem_start_info = process.memory_info()
        mem_start = mem_start_info.rss / (1024 * 1024)  # Get Resident Set Size in MB
        # --- END METRICS ADDITION ---
        
        # Read file data
        file_data = file.read()
        original_filename = secure_filename(file.filename)
        file_size_bytes = len(file_data) # <<< ADDED
        
        # Check file size
        if file_size_bytes > app.config['MAX_CONTENT_LENGTH']: # <<< MODIFIED
            flash('File too large (max 16MB)', 'error')
            return redirect(url_for('index'))
        
        # ML Classification
        ml_result = ml_classifier.predict_sensitivity(file_data, original_filename)
        sensitivity = ml_result['sensitivity']
        confidence = ml_result['confidence']
        features = ml_result['features']
        
        # Get user's appropriate keys
        user_keys = key_storage.get_user_keys(current_user.username, sensitivity)
        public_key = user_keys['public_key']
        
        # Adaptive encryption
        encrypted_file_data, encrypted_aes_key, crypto_config = adaptive_crypto.encrypt_file(
            file_data, public_key, sensitivity
        )
        
        # Save encrypted file
        encrypted_filename = f"enc_{sensitivity.lower()}_{current_user.username}_{int(time.time())}.dat"
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        
        with open(encrypted_filepath, 'w') as f:
            f.write(encrypted_file_data)
        
        # Store in database
        encrypted_file = EncryptedFile(
            user_id=current_user.id,
            filename=encrypted_filename,
            original_filename=original_filename,
            file_size=file_size_bytes, # <<< MODIFIED
            encrypted_aes_key=encrypted_aes_key,
            sensitivity=sensitivity,
            crypto_config=crypto_config,
            ml_confidence=confidence,
            entropy=features['entropy']
        )
        
        db.session.add(encrypted_file)
        db.session.commit()
        
        encryption_time = (time.time() - start_time) * 1000  # ms
        
        # --- ADDED FOR METRICS ---
        cpu_end = process.cpu_percent(interval=None)
        mem_end_info = process.memory_info()
        mem_end = mem_end_info.rss / (1024 * 1024)  # Get Resident Set Size in MB
        cpu_usage = cpu_end - cpu_start
        # --- END METRICS ADDITION ---

        # --- ADDED FOR PERFORMANCE CSV LOGGING --- # <<< ADDED
        try:
            upload_fieldnames = [
                'timestamp', 'username', 'filename', 'file_size_bytes', 
                'sensitivity', 'ml_confidence', 'encryption_time_ms', 
                'cpu_usage_percent', 'memory_usage_mb', 'crypto_config'
            ]
            upload_metrics = {
                'timestamp': datetime.now().isoformat(),
                'username': current_user.username,
                'filename': original_filename,
                'file_size_bytes': file_size_bytes,
                'sensitivity': sensitivity,
                'ml_confidence': confidence,
                'encryption_time_ms': encryption_time,
                'cpu_usage_percent': cpu_usage,
                'memory_usage_mb': mem_end,
                'crypto_config': crypto_config
            }
            write_metrics_to_csv(UPLOAD_PERFORMANCE_CSV, upload_metrics, upload_fieldnames)
        except Exception as e:
            print(f"Failed to log upload performance: {e}")
        # --- END PERFORMANCE LOGGING --- # <<< ADDED

        log_audit('FILE_UPLOAD', 
                 details=f'File: {original_filename}, Sensitivity: {sensitivity}, Time: {encryption_time:.1f}ms, CPU: {cpu_usage:.2f}%, Mem: {mem_end:.2f}MB') # <<< MODIFIED LOG FORMATTING
        
        flash(f'🧠 ML Analysis: {sensitivity} sensitivity ({confidence*100:.1f}% confidence)', 'success')
        flash(f'🔒 Encrypted with {crypto_config} in {encryption_time:.1f}ms', 'success')
        
        return render_template('success_ml_adaptive.html',
                             filename=original_filename,
                             file_id=encrypted_file.id,
                             sensitivity=sensitivity,
                             confidence=confidence,
                             features=features,
                             crypto_config=crypto_config,
                             encryption_time=encryption_time)
    
    except Exception as e:
        db.session.rollback()
        flash(f'❌ Error: {str(e)}', 'error')
        log_audit('FILE_UPLOAD', details=f'Error: {str(e)}', success=False)
        return redirect(url_for('index'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Handle adaptive encrypted file download"""
    try:
        start_time = time.time() # <--- ADDED FOR LATENCY

        # --- ADDED FOR METRICS --- # <<< ADDED
        process = psutil.Process(os.getpid())
        cpu_start = process.cpu_percent(interval=None)
        mem_start_info = process.memory_info()
        mem_start = mem_start_info.rss / (1024 * 1024)
        # --- END METRICS ADDITION --- # <<< ADDED
        
        # Get file metadata - Using the original get_or_404
        file_info = EncryptedFile.query.get_or_404(file_id)
        
        # Check ownership
        if file_info.user_id != current_user.id:
            flash('Access denied', 'error')
            log_audit('FILE_DOWNLOAD', 
                     details=f'Unauthorized access attempt: file_id={file_id}', 
                     success=False)
            return redirect(url_for('index'))
        
        sensitivity = file_info.sensitivity
        
        # Get user's private key
        user_keys = key_storage.get_user_keys(current_user.username, sensitivity)
        private_key = user_keys['private_key']
        
        # Read encrypted file
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, file_info.filename)
        with open(encrypted_filepath, 'r') as f:
            encrypted_file_data = f.read()
        
        # Adaptive decryption
        decrypted_data = adaptive_crypto.decrypt_file(
            encrypted_file_data,
            file_info.encrypted_aes_key,
            private_key,
            sensitivity
        )
        
        decryption_time = (time.time() - start_time) * 1000 # <--- ADDED FOR LATENCY

        # --- ADDED FOR METRICS --- # <<< ADDED
        cpu_end = process.cpu_percent(interval=None)
        mem_end_info = process.memory_info()
        mem_end = mem_end_info.rss / (1024 * 1024)
        cpu_usage = cpu_end - cpu_start
        # --- END METRICS ADDITION --- # <<< ADDED
        
        # Update last accessed
        file_info.update_last_accessed()
        
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(decrypted_data)
        temp_file.close()

        # --- ADDED FOR PERFORMANCE CSV LOGGING --- # <<< ADDED
        try:
            download_fieldnames = [
                'timestamp', 'username', 'filename', 'file_size_bytes',
                'sensitivity', 'decryption_time_ms', 'cpu_usage_percent', 
                'memory_usage_mb'
            ]
            download_metrics = {
                'timestamp': datetime.now().isoformat(),
                'username': current_user.username,
                'filename': file_info.original_filename,
                'file_size_bytes': file_info.file_size,
                'sensitivity': sensitivity,
                'decryption_time_ms': decryption_time,
                'cpu_usage_percent': cpu_usage,
                'memory_usage_mb': mem_end
            }
            write_metrics_to_csv(DOWNLOAD_PERFORMANCE_CSV, download_metrics, download_fieldnames)
        except Exception as e:
            print(f"Failed to log download performance: {e}")
        # --- END PERFORMANCE LOGGING --- # <<< ADDED
        
        log_audit('FILE_DOWNLOAD', 
                 details=f'File: {file_info.original_filename}, Time: {decryption_time:.1f}ms, CPU: {cpu_usage:.2f}%, Mem: {mem_end:.2f}MB') # <<< MODIFIED LOG FORMATTING
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=file_info.original_filename
        )
    
    except Exception as e:
        flash(f'❌ Decryption failed: {str(e)}', 'error')
        log_audit('FILE_DOWNLOAD', 
                 details=f'Error: {str(e)}', 
                 success=False)
        return redirect(url_for('index'))

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete encrypted file"""
    try:
        # Using the original get_or_404
        file_info = EncryptedFile.query.get_or_404(file_id)
        
        # Check ownership
        if file_info.user_id != current_user.id:
            flash('Access denied', 'error')
            return redirect(url_for('index'))
        
        # Delete physical file
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, file_info.filename)
        if os.path.exists(encrypted_filepath):
            os.remove(encrypted_filepath)
        
        # Delete database record
        original_filename = file_info.original_filename
        db.session.delete(file_info)
        db.session.commit()
        
        log_audit('FILE_DELETE', details=f'File: {original_filename}')
        flash(f'File "{original_filename}" deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete file: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/ml-stats')
@login_required
def ml_stats():
    """Show ML model statistics for current user"""
    user_files = EncryptedFile.query.filter_by(user_id=current_user.id).all()
    
    # Convert to dictionary format
    files_dict = {}
    for file in user_files:
        files_dict[str(file.id)] = {
            'original_filename': file.original_filename,
            'sensitivity': file.sensitivity,
            'ml_confidence': file.ml_confidence,
            'entropy': file.entropy,
            'file_size': file.file_size,
            'crypto_config': file.crypto_config
        }
    
    # Calculate statistics
    stats = {
        'total': len(user_files),
        'low': sum(1 for f in user_files if f.sensitivity == 'LOW'),
        'medium': sum(1 for f in user_files if f.sensitivity == 'MEDIUM'),
        'high': sum(1 for f in user_files if f.sensitivity == 'HIGH'),
        'avg_confidence': sum(f.ml_confidence for f in user_files) / len(user_files) if user_files else 0
    }
    
    return render_template('ml_stats.html', stats=stats, files=files_dict)

@app.route('/keys')
@login_required
def show_keys():
    """Show user's encryption keys (debug only - remove in production)"""
    all_keys = key_storage.get_all_user_keys(current_user.username)
    return render_template('keys.html', keys=all_keys, user_id=current_user.username)


# --- ROUTES FOR DOWNLOADING CSV REPORTS --- # <<< ADDED
@app.route('/download/report/upload_metrics')
@login_required
def download_upload_report():
    """Route to download the upload performance CSV."""
    try:
        return send_file(
            UPLOAD_PERFORMANCE_CSV,
            as_attachment=True,
            download_name='upload_performance_metrics.csv',
            mimetype='text/csv'
        )
    except Exception as e:
        flash(f'Could not download report: File not found or error: {e}', 'error')
        return redirect(url_for('index'))

@app.route('/download/report/download_metrics')
@login_required
def download_download_report():
    """Route to download the download performance CSV."""
    try:
        return send_file(
            DOWNLOAD_PERFORMANCE_CSV,
            as_attachment=True,
            download_name='download_performance_metrics.csv',
            mimetype='text/csv'
        )
    except Exception as e:
        flash(f'Could not download report: File not found or error: {e}', 'error')
        return redirect(url_for('index'))
# --- END ADDED --- #


# Error handlers - Keeping original versions
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# CLI commands for database management
@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print('Database initialized!')

@app.cli.command()
def create_admin():
    """Create admin user."""
    username = input('Admin username: ')
    email = input('Admin email: ')
    password = input('Admin password: ')
    
    if User.query.filter_by(username=username).first():
        print('User already exists!')
        return
    
    admin = User(
        username=username,
        email=email,
        full_name='Administrator',
        is_admin=True
    )
    admin.set_password(password)
    
    db.session.add(admin)
    db.session.commit()
    
    # Generate keys
    from crypto_utils_adaptive import adaptive_crypto
    from key_storage import key_storage
    
    for sensitivity in ['LOW', 'MEDIUM', 'HIGH']:
        public_key, private_key, config_name = adaptive_crypto.generate_key_pair(sensitivity)
        key_storage.store_user_keys(public_key, private_key, username, sensitivity)
    
    print(f'Admin user "{username}" created successfully!')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    print("🚀 Starting ML-Adaptive Secure File Storage System with Authentication...")
    print("📊 ML Model will train on first run if not found")
    print("🌐 Open http://localhost:5000 in your browser")
    print("🔐 You need to register/login to access the system")
    app.run(debug=True, port=5000)