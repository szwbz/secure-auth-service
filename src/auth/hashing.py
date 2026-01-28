import bcrypt
import hashlib
import os
from typing import Tuple

class PasswordHasher:
    """
    Secure password hashing implementation using bcrypt with salt.
    """
    
    def __init__(self, rounds: int = 12):
        """
        Initialize the password hasher.
        
        Args:
            rounds: Number of bcrypt rounds (higher = more secure but slower)
        """
        self.rounds = rounds
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt with a random salt.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Hashed password as a string
        """
        # Generate salt and hash the password
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Hashed password to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError):
            return False
    
    def generate_peppered_hash(self, password: str, pepper: str) -> str:
        """
        Generate a hash with additional pepper (secret key).
        This adds defense against rainbow table attacks if the database is compromised.
        
        Args:
            password: Plain text password
            pepper: Secret pepper string
            
        Returns:
            Hashed password with pepper
        """
        # Combine password with pepper before hashing
        peppered = password + pepper
        return self.hash_password(peppered)
    
    def verify_peppered_password(self, password: str, pepper: str, hashed_password: str) -> bool:
        """
        Verify a password with pepper.
        
        Args:
            password: Plain text password
            pepper: Secret pepper string
            hashed_password: Hashed password to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        peppered = password + pepper
        return self.verify_password(peppered, hashed_password)


def create_sha256_hash(data: str, salt: str = None) -> Tuple[str, str]:
    """
    Create a SHA-256 hash for general data (not passwords).
    
    Args:
        data: Data to hash
        salt: Optional salt (if None, generates random salt)
        
    Returns:
        Tuple of (hash, salt_used)
    """
    if salt is None:
        salt = os.urandom(16).hex()
    
    # Combine data with salt
    salted_data = data + salt
    hash_obj = hashlib.sha256(salted_data.encode('utf-8'))
    return hash_obj.hexdigest(), salt


def verify_sha256_hash(data: str, expected_hash: str, salt: str) -> bool:
    """
    Verify a SHA-256 hash.
    
    Args:
        data: Data to verify
        expected_hash: Expected hash value
        salt: Salt used in original hash
        
    Returns:
        True if hash matches, False otherwise
    """
    hash_obj = hashlib.sha256((data + salt).encode('utf-8'))
    return hash_obj.hexdigest() == expected_hash


# Default hasher instance
default_hasher = PasswordHasher()