import secrets
import string

class PasswordGenerator:
    @staticmethod
    def generate_strong_password(length=16):
        """
        Generate a strong random password
        
        Args:
            length (int, optional): Password length. Defaults to 16.
        
        Returns:
            str: Generated strong password
        """
        # Define character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special_chars = string.punctuation
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special_chars)
        ]
        
        # Fill the rest of the password
        all_chars = uppercase + lowercase + digits + special_chars
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)