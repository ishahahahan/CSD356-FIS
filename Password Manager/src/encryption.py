import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class EncryptionManager:
    @staticmethod
    def generate_key(master_password, salt=None):
        """
        Generate a secure encryption key from master password
        
        Args:
            master_password (str): Master password for key generation
            salt (bytes, optional): Salt for key derivation. Generates if not provided.
        
        Returns:
            tuple: (encryption key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_data(data, key):
        """
        Encrypt data using Fernet encryption
        
        Args:
            data (str): Data to encrypt
            key (bytes): Encryption key
        
        Returns:
            str: Encrypted data
        """
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        """
        Decrypt data using Fernet encryption
        
        Args:
            encrypted_data (str): Encrypted data
            key (bytes): Decryption key
        
        Returns:
            str: Decrypted data
        """
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()