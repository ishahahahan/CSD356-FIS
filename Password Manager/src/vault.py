import base64
import os
import json
import uuid
from .encryption import EncryptionManager
from .password_checker import PasswordChecker

class PasswordVault:
    def __init__(self, vault_id=None, vault_dir='vaults'):
        """
        Initialize Password Vault
        
        Args:
            vault_id (str, optional): Unique ID for the vault. Generated if None.
            vault_dir (str, optional): Directory to store vault files
        """
        # Create vaults directory if it doesn't exist
        if not os.path.exists(vault_dir):
            os.makedirs(vault_dir)
        
        self.vault_dir = vault_dir
        
        # Generate or use provided vault ID
        self.vault_id = vault_id if vault_id else str(uuid.uuid4())
        
        # Set vault-specific file paths
        self.vault_file = os.path.join(vault_dir, f'{self.vault_id}_password_vault.json')
        self.master_key_file = os.path.join(vault_dir, f'{self.vault_id}_master_key.key')
        
        # Initialize empty password dictionary
        self.passwords = {}
        
        # Load existing passwords if vault file exists
        self.load_passwords()
    
    def load_passwords(self):
        """Load passwords from vault file if it exists"""
        if os.path.exists(self.vault_file):
            try:
                with open(self.vault_file, 'r') as file:
                    self.passwords = json.load(file)
            except json.JSONDecodeError:
                # Handle corrupted JSON file
                print(f"Warning: Could not load vault file {self.vault_file}. Creating new vault.")
                self.passwords = {}
    
    def create_master_password(self, master_password):
        """
        Create master password and encryption key with debugging
        
        Args:
            master_password (str): Master password to set
        
        Raises:
            ValueError: If password is too weak
        
        Returns:
            bytes: Generated encryption key
        """
        import base64
        
        # Check password strength
        if not PasswordChecker.is_password_strong(master_password):
            raise ValueError("Master password is too weak. Please choose a stronger password.")
        
        # Generate encryption key
        key, salt = EncryptionManager.generate_key(master_password)
        
        # Print diagnostic information
        print("Salt:", base64.b64encode(salt).decode())
        print("Key:", base64.b64encode(key).decode())
        
        # Save salt and encrypted key
        with open(self.master_key_file, 'wb') as f:
            f.write(salt + base64.urlsafe_b64encode(key))
        
        # Create vault info file to store metadata
        vault_info = {
            'vault_id': self.vault_id,
            'created_at': str(uuid.uuid1()),  # Includes timestamp
            'name': f'Vault {self.vault_id[:8]}'
        }
        
        info_file = os.path.join(self.vault_dir, f'{self.vault_id}_info.json')
        with open(info_file, 'w') as f:
            json.dump(vault_info, f)
        
        return key
    
    def verify_master_password(self, input_password):
        """
        Verify master password with improved debugging
        
        Args:
            input_password (str): Password to verify
        
        Returns:
            bool: True if password is correct, False otherwise
        """
        import base64
        
        # Check if master key file exists
        if not os.path.exists(self.master_key_file):
            print(f"Master key file does not exist: {self.master_key_file}")
            return False
        
        try:
            # Read stored master key data
            with open(self.master_key_file, 'rb') as f:
                stored_data = f.read()
            
            # Extract salt and stored key
            salt = stored_data[:16]
            stored_key = base64.urlsafe_b64decode(stored_data[16:])
            
            # Generate key from input password
            generated_key, _ = EncryptionManager.generate_key(input_password, salt)
            
            # Compare generated key with stored key
            is_match = base64.urlsafe_b64encode(generated_key) == base64.urlsafe_b64encode(stored_key)
            
            # Diagnostic print statements
            print("Salt:", base64.b64encode(salt).decode())
            print("Stored Key:", base64.b64encode(stored_key).decode())
            print("Generated Key:", base64.b64encode(generated_key).decode())
            print("Password Match:", is_match)
            
            return is_match
        
        except Exception as e:
            print(f"Error during password verification: {e}")
            return False
    
    def add_password(self, service, username, password, encryption_key):
        """
        Add a new password to the vault
        
        Args:
            service (str): Service/website name
            username (str): Username for the service
            password (str): Password for the service
            encryption_key (bytes): Encryption key
        """
        # Make sure we have the latest passwords
        self.load_passwords()
        
        # Encrypt username and password
        encrypted_username = EncryptionManager.encrypt_data(username, encryption_key)
        encrypted_password = EncryptionManager.encrypt_data(password, encryption_key)
        
        # Store in passwords dictionary
        self.passwords[service] = {
            'username': encrypted_username,
            'password': encrypted_password
        }
        
        # Save to file
        with open(self.vault_file, 'w') as file:
            json.dump(self.passwords, file)
    
    def get_password(self, service, encryption_key):
        """
        Retrieve a password from the vault
        
        Args:
            service (str): Service/website name
            encryption_key (bytes): Decryption key
        
        Returns:
            tuple: (decrypted username, decrypted password)
        """
        # Make sure we have the latest passwords
        self.load_passwords()
        
        if service not in self.passwords:
            return None, None
        
        # Decrypt username and password
        encrypted_username = self.passwords[service]['username']
        encrypted_password = self.passwords[service]['password']
        
        decrypted_username = EncryptionManager.decrypt_data(encrypted_username, encryption_key)
        decrypted_password = EncryptionManager.decrypt_data(encrypted_password, encryption_key)
        
        return decrypted_username, decrypted_password
    
    @staticmethod
    def list_vaults(vault_dir='vaults'):
        """
        List all available vaults
        
        Args:
            vault_dir (str): Directory where vaults are stored
        
        Returns:
            list: List of tuples (vault_id, vault_name)
        """
        vaults = []
        
        if not os.path.exists(vault_dir):
            return vaults
            
        for file in os.listdir(vault_dir):
            if file.endswith('_info.json'):
                try:
                    with open(os.path.join(vault_dir, file), 'r') as f:
                        info = json.load(f)
                        vaults.append((info['vault_id'], info.get('name', f"Vault {info['vault_id'][:8]}")))
                except:
                    # Skip files that can't be loaded
                    continue
                    
        return vaults