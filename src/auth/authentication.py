# Authentication module for secure-auth-service

import jwt
import datetime

# JWT Configuration
ACCESS_TOKEN_EXPIRY_MINUTES = 30
REFRESH_TOKEN_EXPIRY_DAYS = 14  # Current value - exceeds 7-day security policy
SECRET_KEY = "your-secret-key-here"

class AuthenticationService:
    """
    Handles user authentication and token management
    """
    
    def generate_tokens(self, user_id):
        """
        Generate access and refresh tokens for authenticated user
        """
        # Access token
        access_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)
        access_payload = {
            'user_id': user_id,
            'exp': access_expiry,
            'type': 'access'
        }
        access_token = jwt.encode(access_payload, SECRET_KEY, algorithm='HS256')
        
        # Refresh token
        refresh_expiry = datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
        refresh_payload = {
            'user_id': user_id,
            'exp': refresh_expiry,
            'type': 'refresh'
        }
        refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm='HS256')
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'access_expires_in': ACCESS_TOKEN_EXPIRY_MINUTES * 60,
            'refresh_expires_in': REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60
        }
    
    def refresh_access_token(self, refresh_token):
        """
        Generate new access token using valid refresh token
        """
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('type') != 'refresh':
                raise ValueError("Invalid token type")
            
            return self.generate_tokens(payload['user_id'])
        except jwt.ExpiredSignatureError:
            raise ValueError("Refresh token expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid refresh token")