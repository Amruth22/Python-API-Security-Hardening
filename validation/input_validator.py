"""
Input Validator
Validates and sanitizes user input
"""

import re
import logging
import html

logger = logging.getLogger(__name__)


class InputValidator:
    """
    Input validation and sanitization
    """
    
    def __init__(self):
        logger.info("Input Validator initialized")
    
    def validate_email(self, email):
        """
        Validate email format
        
        Args:
            email: Email string to validate
            
        Returns:
            True if valid, False otherwise
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def validate_username(self, username):
        """
        Validate username format
        
        Args:
            username: Username to validate
            
        Returns:
            True if valid, False otherwise
        """
        # 3-20 characters, alphanumeric and underscore only
        pattern = r'^[a-zA-Z][a-zA-Z0-9_]{2,19}$'
        return bool(re.match(pattern, username))
    
    def validate_password(self, password):
        """
        Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Dictionary with validation results
        """
        results = {
            'valid': True,
            'errors': []
        }
        
        if len(password) < 8:
            results['valid'] = False
            results['errors'].append('Password must be at least 8 characters')
        
        if not any(c.isupper() for c in password):
            results['valid'] = False
            results['errors'].append('Password must contain uppercase letter')
        
        if not any(c.islower() for c in password):
            results['valid'] = False
            results['errors'].append('Password must contain lowercase letter')
        
        if not any(c.isdigit() for c in password):
            results['valid'] = False
            results['errors'].append('Password must contain digit')
        
        return results
    
    def sanitize_string(self, input_str):
        """
        Sanitize string input
        
        Args:
            input_str: String to sanitize
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_str, str):
            return input_str
        
        # HTML escape
        sanitized = html.escape(input_str)
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Trim whitespace
        sanitized = sanitized.strip()
        
        return sanitized
    
    def sanitize_dict(self, data):
        """
        Sanitize dictionary data
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [self.sanitize_string(v) if isinstance(v, str) else v for v in value]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def validate_json_structure(self, data, required_fields):
        """
        Validate JSON structure
        
        Args:
            data: JSON data to validate
            required_fields: List of required field names
            
        Returns:
            Dictionary with validation results
        """
        results = {
            'valid': True,
            'errors': []
        }
        
        if not isinstance(data, dict):
            results['valid'] = False
            results['errors'].append('Data must be a dictionary')
            return results
        
        for field in required_fields:
            if field not in data:
                results['valid'] = False
                results['errors'].append(f'Missing required field: {field}')
        
        return results
    
    def validate_integer(self, value, min_val=None, max_val=None):
        """
        Validate integer value
        
        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            
        Returns:
            True if valid, False otherwise
        """
        try:
            int_val = int(value)
            
            if min_val is not None and int_val < min_val:
                return False
            
            if max_val is not None and int_val > max_val:
                return False
            
            return True
        except (ValueError, TypeError):
            return False
    
    def is_safe_filename(self, filename):
        """
        Check if filename is safe
        
        Args:
            filename: Filename to check
            
        Returns:
            True if safe, False otherwise
        """
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        # Check for null bytes
        if '\x00' in filename:
            return False
        
        # Check for valid characters
        pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(pattern, filename))
