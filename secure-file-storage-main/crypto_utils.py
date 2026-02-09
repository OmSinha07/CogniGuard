from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os

class CryptoManager:
    """Handles all cryptographic operations"""
    
    def __init__(self):
        self.key_size = 2048  # RSA key size
        self.aes_key_size = 32  # 256-bit AES key
    
    def generate_key_pair(self):
        """Generate RSA public/private key pair"""
        key = RSA.generate(self.key_size)
        
        # Export keys as strings
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        
        return public_key, private_key
    
    def encrypt_file(self, file_data, public_key_str):
        """
        Encrypt file using hybrid cryptography (AES + RSA)
        Returns: (encrypted_file_data, encrypted_aes_key)
        """
        try:
            # Step 1: Generate random AES key
            aes_key = get_random_bytes(self.aes_key_size)
            
            # Step 2: Encrypt file with AES
            cipher_aes = AES.new(aes_key, AES.MODE_CBC)
            iv = cipher_aes.iv  # Initialization vector
            
            # Pad data to be multiple of block size
            padded_data = pad(file_data, AES.block_size)
            encrypted_file = cipher_aes.encrypt(padded_data)
            
            # Combine IV + encrypted data
            encrypted_file_data = iv + encrypted_file
            
            # Step 3: Encrypt AES key with RSA public key
            public_key = RSA.import_key(public_key_str)
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            # Convert to base64 for storage
            encrypted_file_b64 = base64.b64encode(encrypted_file_data).decode('utf-8')
            encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
            
            return encrypted_file_b64, encrypted_key_b64
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_file_b64, encrypted_key_b64, private_key_str):
        """
        Decrypt file using hybrid cryptography
        Returns: original_file_data
        """
        try:
            # Convert from base64
            encrypted_file_data = base64.b64decode(encrypted_file_b64)
            encrypted_aes_key = base64.b64decode(encrypted_key_b64)
            
            # Step 1: Decrypt AES key with RSA private key
            private_key = RSA.import_key(private_key_str)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            # Step 2: Extract IV and encrypted data
            iv = encrypted_file_data[:16]  # First 16 bytes are IV
            encrypted_data = encrypted_file_data[16:]
            
            # Step 3: Decrypt file with AES
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = cipher_aes.decrypt(encrypted_data)
            
            # Remove padding
            original_data = unpad(padded_data, AES.block_size)
            
            return original_data
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

# Global instance
crypto_manager = CryptoManager()

