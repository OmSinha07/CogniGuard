# ============================================
# FILE 3: crypto_utils_adaptive.py (NEW)
# ============================================

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class AdaptiveCryptoManager:
    """Adaptive cryptography based on ML classification"""
    
    def __init__(self):
        # Encryption configurations for each sensitivity level
        self.configs = {
            'LOW': {
                'aes_key_size': 16,    # 128-bit
                'rsa_key_size': 1024,  # 1024-bit
                'name': 'AES-128 + RSA-1024',
                'speed': 'Fast',
                'security': 'Standard'
            },
            'MEDIUM': {
                'aes_key_size': 24,    # 192-bit
                'rsa_key_size': 2048,  # 2048-bit
                'name': 'AES-192 + RSA-2048',
                'speed': 'Balanced',
                'security': 'High'
            },
            'HIGH': {
                'aes_key_size': 32,    # 256-bit
                'rsa_key_size': 4096,  # 4096-bit
                'name': 'AES-256 + RSA-4096',
                'speed': 'Slower',
                'security': 'Maximum'
            }
        }
    
    def generate_key_pair(self, sensitivity='MEDIUM'):
        """Generate RSA key pair based on sensitivity"""
        config = self.configs[sensitivity]
        key_size = config['rsa_key_size']
        
        key = RSA.generate(key_size)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        
        return public_key, private_key, config['name']
    
    def encrypt_file(self, file_data, public_key_str, sensitivity='MEDIUM'):
        """Encrypt file with adaptive algorithm selection"""
        try:
            config = self.configs[sensitivity]
            aes_key_size = config['aes_key_size']
            
            # Step 1: Generate random AES key (adaptive size)
            aes_key = get_random_bytes(aes_key_size)
            
            # Step 2: Encrypt file with AES
            cipher_aes = AES.new(aes_key, AES.MODE_CBC)
            iv = cipher_aes.iv
            
            padded_data = pad(file_data, AES.block_size)
            encrypted_file = cipher_aes.encrypt(padded_data)
            
            encrypted_file_data = iv + encrypted_file
            
            # Step 3: Encrypt AES key with RSA
            public_key = RSA.import_key(public_key_str)
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            # Convert to base64
            encrypted_file_b64 = base64.b64encode(encrypted_file_data).decode('utf-8')
            encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
            
            return encrypted_file_b64, encrypted_key_b64, config['name']
            
        except Exception as e:
            raise Exception(f"Adaptive encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_file_b64, encrypted_key_b64, private_key_str, sensitivity='MEDIUM'):
        """Decrypt file with matching algorithm"""
        try:
            config = self.configs[sensitivity]
            
            # Convert from base64
            encrypted_file_data = base64.b64decode(encrypted_file_b64)
            encrypted_aes_key = base64.b64decode(encrypted_key_b64)
            
            # Decrypt AES key with RSA
            private_key = RSA.import_key(private_key_str)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            # Extract IV and encrypted data
            iv = encrypted_file_data[:16]
            encrypted_data = encrypted_file_data[16:]
            
            # Decrypt file with AES
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = cipher_aes.decrypt(encrypted_data)
            original_data = unpad(padded_data, AES.block_size)
            
            return original_data
            
        except Exception as e:
            raise Exception(f"Adaptive decryption failed: {str(e)}")
    
    def get_config(self, sensitivity):
        """Get encryption configuration for sensitivity level"""
        return self.configs.get(sensitivity, self.configs['MEDIUM'])

# Global instance
adaptive_crypto = AdaptiveCryptoManager()


