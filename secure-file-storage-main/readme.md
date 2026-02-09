# 🔒 Secure File Storage System (ML-Adaptive)

A Flask-based secure file storage system using user authentication, ML-based sensitivity classification, and adaptive hybrid cryptography for zero-knowledge file encryption.

---

## 🌟 Features

### ✅ Current Version

- **🧠 ML-Powered Sensitivity Analysis** - Automatically classifies files (LOW, MEDIUM, HIGH) based on content, extension, and entropy.
- **🔐 Adaptive Hybrid Cryptography** - Applies encryption strength matching the file's sensitivity (e.g., AES-128 + RSA-1024 for LOW, AES-256 + RSA-4096 for HIGH).
- **👥 Multi-User Authentication** - Secure user registration and login system with password hashing and validation.
- **🛡️ Per-User, Per-Sensitivity Keys** - Each user gets unique RSA key pairs generated for each sensitivity level (LOW, MEDIUM, HIGH).
- **🗄️ Database Storage** - Uses SQLAlchemy (SQLite by default) to store user info, encrypted file metadata, and audit logs.
- **🧾 Audit Logging** - Tracks key events like login, upload, download, and delete for security monitoring (now includes performance metrics).
- **📊 Performance Logging** - Tracks detailed metrics (CPU usage, memory, execution time) for all upload and download operations, saving them to CSV reports.
- **🔑 Zero-Knowledge Architecture** - The server and administrators have no access to the private keys or plaintext file data.
- **📁 User Dashboard & Profile** - Users can manage their files and view personal stats like storage used and file sensitivity breakdown.

### ⏳ Planned Features (Future Phases)

- **🤝 File Sharing** - Securely share encrypted files between users.
- **☁️ Cloud Storage Integration** - AWS S3 compatibility.
- **📱 Modern UI** - React frontend with drag-and-drop.
- **🔗 API Endpoints** - RESTful API for third-party integrations.

---

## 🏗️ System Architecture

### ML-Adaptive Encryption Flow

**Upload:**
```
File → ML Sensitivity Analysis (e.g., "HIGH")
     → Select HIGH Config (AES-256 + RSA-4096)
     → Encrypt File with AES-256
     → Encrypt AES key with User's "HIGH" RSA-4096 Public Key
     → Log Performance (CPU, Mem, Time) to CSV
     → Store in DB & Filesystem
```

**Download:**
```
Request File
     → Fetch Encrypted Data + Encrypted AES Key
     → Get User's "HIGH" RSA-4096 Private Key
     → Decrypt AES key with RSA Private Key
     → Decrypt File with AES Key
     → Log Performance (CPU, Mem, Time) to CSV
     → Return Original File
```

### Security Model

- **Files:** Encrypted with unique AES keys (128, 192, or 256-bit) based on ML-defined sensitivity.
- **Keys:** AES keys are encrypted with the user's corresponding RSA public key (1024, 2048, or 4096-bit).
- **Storage:** All file data is stored encrypted. All keys are stored encrypted (AES keys) or are user-specific (RSA keys).
- **Authentication:** User passwords are securely hashed using werkzeug.security.
- **Zero-Knowledge:** The server never holds a user's private key or plaintext file data. Decryption only happens on the user's side (conceptually) or ephemerally during the download request, protected by the user's login session.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/secure-file-storage.git
cd secure-file-storage
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Initialize the database**

```bash
flask init-db
```

4. **Create an admin user** (Optional, but recommended)

```bash
flask create-admin
# Follow prompts for username, email, and password
```

5. **Run the application**

```bash
python app_with_auth.py
```

6. **Open your browser**

Navigate to `http://localhost:5000`

You will be redirected to the login page. Register a new user or log in with the admin account.

---

## 🛠️ Technology Stack

### Backend
- **Flask** - Web framework
- **Flask-Login** - User session management
- **Flask-SQLAlchemy** - Database ORM
- **Werkzeug** - Password hashing, file handling
- **psutil** - System performance metrics (CPU, Memory)

### ML / Data
- **scikit-learn** - ML model for file classification
- **joblib** - Model persistence
- **pandas** - Data handling for ML

### Cryptography
- **pycryptodome** - Cryptographic operations
- **AES-CBC** (128/192/256-bit) - Adaptive file encryption
- **RSA-OAEP** (1024/2048/4096-bit) - Adaptive key encryption
- **Base64** - Binary data handling

### Storage
- **SQLite** - Default database for users, files, and logs
- **Local Filesystem** - Storage for encrypted file blobs (`encrypted_uploads/`)

---

## 📁 Project Structure

```
secure-file-storage/
├── app_with_auth.py          # Main Flask application with auth
├── auth.py                   # Authentication routes blueprint (login, register)
├── ml_classifier.py          # ML model for sensitivity classification
├── crypto_utils_adaptive.py  # Adaptive crypto logic (AES/RSA)
├── key_storage.py            # Manages storage/retrieval of user keys
├── models.py                 # SQLAlchemy database models (User, EncryptedFile)
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── .gitignore                # Git ignore rules
├── templates/
│   ├── index_ml_adaptive.html  # Main file dashboard
│   ├── login.html              # Login page
│   ├── register.html           # Registration page
│   ├── profile.html            # User profile page
│   ├── ml_stats.html           # ML statistics view
│   ├── keys.html               # Key viewing page (debug)
│   └── ... (other html files)
├── encrypted_uploads/        # Encrypted file data
├── secure_storage.db         # SQLite Database (auto-generated)
├── ml_model.pkl              # Trained ML model (auto-generated)
├── upload_performance_metrics.csv   # Performance log (auto-generated)
└── download_performance_metrics.csv # Performance log (auto-generated)
```

---

## 🧪 Testing Your Installation

1. **Register a User:** Go to `http://localhost:5000/auth/register` and create an account.
2. **Log In:** Log in with your new credentials.
3. **Upload Files:** Upload various files (e.g., `.txt`, `.jpg`, `.pdf`, `.zip`).
4. **Check Dashboard:** Observe the "Sensitivity" and "Crypto Config" columns. You should see different values (e.g., LOW, MEDIUM) based on the files you uploaded.
5. **Download Files:** Download your files and verify they are identical to the originals.
6. **Check Database:** Use a tool like "DB Browser for SQLite" to open `secure_storage.db` and inspect the `user`, `encrypted_file`, and `audit_log` tables.
7. **Check File Storage:** Look in the `encrypted_uploads/` directory. All files should have names like `enc_low_username_12345.dat` and contain unreadable gibberish.
8. **Check Performance Logs:** After uploading and downloading, check the project directory for `upload_performance_metrics.csv` and `download_performance_metrics.csv`. These files will contain detailed performance data for each operation.

---

## 🆘 Troubleshooting

### ImportError: No module named 'Crypto'

You have the wrong library. Install `pycryptodome`.

```bash
pip uninstall pycrypto
pip install pycryptodome
```

### Files not encrypting / App crashing

- Ensure `pycryptodome`, `scikit-learn`, `flask_login`, and `psutil` are installed: `pip install -r requirements.txt`.
- Make sure you ran `flask init-db` before running the app for the first time.
- Check that the `ml_model.pkl` file was created (it should be trained automatically on the first run if not present).

### Permission Errors

Run your terminal as an administrator or ensure you have write permissions in the project directory (for creating the `.db` file, `encrypted_uploads/` folder, and `.csv` performance logs).

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

## ⚠️ Security Notice

**This is an educational project.** For production use, conduct a thorough security audit and follow industry best practices.