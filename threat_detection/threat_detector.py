"""
Threat Detector
Detects common security threats in API requests
"""

import re
import logging

logger = logging.getLogger(__name__)


class ThreatDetector:
    """
    Threat detection system
    Detects SQL injection, XSS, and other common attacks
    """
    
    def __init__(self):
        # SQL injection patterns
        self.sql_patterns = [
            r"(\bSELECT\b.*\bFROM\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bUNION\b.*\bSELECT\b)",
            r"(--)",
            r"(;.*--)",
            r"(\bOR\b.*=.*)",
            r"('.*OR.*'.*=.*')"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe",
            r"<object",
            r"<embed"
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.",
            r"%2e%2e",
            r"\.\.\\",
        ]
        
        logger.info("Threat Detector initialized")
    
    def detect_sql_injection(self, input_data):
        """
        Detect SQL injection attempts
        
        Args:
            input_data: Input string to check
            
        Returns:
            True if SQL injection detected, False otherwise
        """
        if not isinstance(input_data, str):
            return False
        
        for pattern in self.sql_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"SQL injection detected: {input_data[:50]}")
                return True
        
        return False
    
    def detect_xss(self, input_data):
        """
        Detect XSS (Cross-Site Scripting) attempts
        
        Args:
            input_data: Input string to check
            
        Returns:
            True if XSS detected, False otherwise
        """
        if not isinstance(input_data, str):
            return False
        
        for pattern in self.xss_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"XSS detected: {input_data[:50]}")
                return True
        
        return False
    
    def detect_path_traversal(self, input_data):
        """
        Detect path traversal attempts
        
        Args:
            input_data: Input string to check
            
        Returns:
            True if path traversal detected, False otherwise
        """
        if not isinstance(input_data, str):
            return False
        
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"Path traversal detected: {input_data[:50]}")
                return True
        
        return False
    
    def detect_threats(self, data):
        """
        Detect any threats in data
        
        Args:
            data: Dictionary or string to check
            
        Returns:
            Threat type if detected, None otherwise
        """
        if isinstance(data, dict):
            # Check all string values in dict
            for key, value in data.items():
                threat = self.detect_threats(value)
                if threat:
                    return threat
        
        elif isinstance(data, str):
            if self.detect_sql_injection(data):
                return "SQL Injection"
            
            if self.detect_xss(data):
                return "XSS"
            
            if self.detect_path_traversal(data):
                return "Path Traversal"
        
        elif isinstance(data, list):
            # Check all items in list
            for item in data:
                threat = self.detect_threats(item)
                if threat:
                    return threat
        
        return None
    
    def sanitize_input(self, input_data):
        """
        Sanitize input data
        
        Args:
            input_data: Input to sanitize
            
        Returns:
            Sanitized input
        """
        if isinstance(input_data, str):
            # Remove dangerous characters
            sanitized = input_data.replace('<', '').replace('>', '')
            sanitized = sanitized.replace('"', '').replace("'", '')
            sanitized = sanitized.replace(';', '').replace('--', '')
            return sanitized.strip()
        
        elif isinstance(input_data, dict):
            return {k: self.sanitize_input(v) for k, v in input_data.items()}
        
        elif isinstance(input_data, list):
            return [self.sanitize_input(item) for item in input_data]
        
        return input_data
    
    def get_threat_stats(self):
        """Get threat detection statistics"""
        return {
            'sql_patterns': len(self.sql_patterns),
            'xss_patterns': len(self.xss_patterns),
            'path_traversal_patterns': len(self.path_traversal_patterns)
        }
