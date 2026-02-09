
# ============================================
# FILE 4: key_storage.py (UPDATED)
# ============================================

import json
import os

class KeyStorage:
    """Enhanced key storage supporting multiple sensitivity levels"""
    
    def __init__(self, storage_file='user_keys.json'):
        self.storage_file = storage_file
        self.keys = self.load_keys()
    
    def load_keys(self):
        """Load keys from file"""
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_keys(self):
        """Save keys to file"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def get_user_keys(self, user_id='default_user', sensitivity='MEDIUM'):
        """Get user's key pair for specific sensitivity level"""
        user_data = self.keys.get(user_id, {})
        
        # Return keys for specific sensitivity level
        if sensitivity in user_data:
            return user_data[sensitivity]
        
        # Fallback to MEDIUM if specific level not found
        return user_data.get('MEDIUM', {})
    
    def store_user_keys(self, public_key, private_key, user_id='default_user', sensitivity='MEDIUM'):
        """Store user's key pair for specific sensitivity level"""
        if user_id not in self.keys:
            self.keys[user_id] = {}
        
        self.keys[user_id][sensitivity] = {
            'public_key': public_key,
            'private_key': private_key
        }
        self.save_keys()
    
    def has_user_keys(self, user_id='default_user', sensitivity=None):
        """Check if user has keys (optionally for specific sensitivity)"""
        if user_id not in self.keys:
            return False
        
        if sensitivity:
            return sensitivity in self.keys[user_id]
        
        # Check if user has any keys
        return len(self.keys[user_id]) > 0
    
    def get_all_user_keys(self, user_id='default_user'):
        """Get all key pairs for a user (all sensitivity levels)"""
        return self.keys.get(user_id, {})

# Global instance
key_storage = KeyStorage()

