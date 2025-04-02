import zxcvbn

class PasswordChecker:
    @staticmethod
    def check_password_strength(password):
        """
        Check password strength using zxcvbn library
        
        Args:
            password (str): Password to check
        
        Returns:
            dict: Password strength analysis
        """
        return zxcvbn.zxcvbn(password)
    
    @staticmethod
    def is_password_strong(password, min_score=3):
        """
        Determine if password is strong enough
        
        Args:
            password (str): Password to evaluate
            min_score (int, optional): Minimum acceptable strength score. Defaults to 3.
        
        Returns:
            bool: True if password meets strength requirements, False otherwise
        """
        strength = zxcvbn.zxcvbn(password)
        return strength['score'] >= min_score