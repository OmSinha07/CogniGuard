
# ============================================
# FILE 5: file_storage.py (UPDATED)
# ============================================

import json
import os
from datetime import datetime

class FileStorage:
    """Enhanced file storage with ML metadata support"""
    
    def __init__(self, storage_file='file_metadata.json'):
        self.storage_file = storage_file
        self.files = self.load_files()
    
    def load_files(self):
        """Load file metadata"""
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_files(self):
        """Save file metadata"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.files, f, indent=2)
    
    def store_file_info(self, filename, original_filename, encrypted_key, file_size, 
                       user_id='default_user', sensitivity='MEDIUM', ml_confidence=0.0, 
                       entropy=0.0, crypto_config='AES-256 + RSA-2048'):
        """Store file metadata with ML analysis results"""
        file_id = f"{user_id}_{len(self.files)}"
        
        self.files[file_id] = {
            'filename': filename,
            'original_filename': original_filename,
            'encrypted_aes_key': encrypted_key,
            'file_size': file_size,
            'user_id': user_id,
            'uploaded_at': datetime.now().isoformat(),
            
            # ML-specific fields
            'sensitivity': sensitivity,
            'ml_confidence': ml_confidence,
            'entropy': entropy,
            'crypto_config': crypto_config
        }
        
        self.save_files()
        return file_id
    
    def get_file_info(self, file_id):
        """Get file metadata by ID"""
        return self.files.get(file_id)
    
    def get_user_files(self, user_id='default_user'):
        """Get all files for a user"""
        return {fid: info for fid, info in self.files.items() 
                if info.get('user_id') == user_id}
    
    def delete_file_info(self, file_id):
        """Delete file metadata"""
        if file_id in self.files:
            del self.files[file_id]
            self.save_files()

# Global instance
file_storage = FileStorage()