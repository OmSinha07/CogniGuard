# ============================================
# FILE: models.py - User Database Models
# ============================================

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model with authentication and profile data"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Profile fields
    full_name = db.Column(db.String(150))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(100), unique=True, nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    files = db.relationship('EncryptedFile', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    sessions = db.relationship('UserSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_reset_token(self):
        """Generate password reset token"""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        return self.password_reset_token
    
    def reset_failed_attempts(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        db.session.commit()
    
    def increment_failed_attempts(self):
        """Increment failed login attempts and lock if needed"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    
    def is_account_locked(self):
        """Check if account is locked"""
        if self.account_locked_until and datetime.utcnow() < self.account_locked_until:
            return True
        return False
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        self.reset_failed_attempts()
        db.session.commit()
    
    def __repr__(self):
        return f'<User {self.username}>'


class EncryptedFile(db.Model):
    """File metadata with user ownership"""
    __tablename__ = 'encrypted_files'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # File info
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    
    # Encryption info
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    sensitivity = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH
    crypto_config = db.Column(db.String(50), nullable=False)
    
    # ML Analysis
    ml_confidence = db.Column(db.Float, default=0.0)
    entropy = db.Column(db.Float, default=0.0)
    
    # Timestamps
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    
    # Sharing (for future feature)
    is_shared = db.Column(db.Boolean, default=False)
    
    def update_last_accessed(self):
        """Update last access timestamp"""
        self.last_accessed = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<EncryptedFile {self.original_filename}>'


class UserSession(db.Model):
    """Track user sessions for security"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def is_expired(self):
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f'<UserSession {self.session_token[:10]}...>'


class AuditLog(db.Model):
    """Audit log for security events"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    action = db.Column(db.String(50), nullable=False)  # LOGIN, LOGOUT, UPLOAD, DOWNLOAD, etc.
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    success = db.Column(db.Boolean, default=True)
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'