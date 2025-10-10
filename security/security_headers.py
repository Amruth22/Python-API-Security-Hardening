"""
Security Headers
Add HTTP security headers to responses
"""

import logging

logger = logging.getLogger(__name__)


class SecurityHeaders:
    """
    Security headers middleware
    Adds security-related HTTP headers to all responses
    """
    
    def __init__(self, app=None):
        """
        Initialize security headers
        
        Args:
            app: Flask app instance
        """
        self.headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
        
        if app:
            self.init_app(app)
        
        logger.info("Security Headers initialized")
    
    def init_app(self, app):
        """
        Initialize with Flask app
        
        Args:
            app: Flask app instance
        """
        app.after_request(self.add_headers)
    
    def add_headers(self, response):
        """
        Add security headers to response
        
        Args:
            response: Flask response object
            
        Returns:
            Modified response with security headers
        """
        for header, value in self.headers.items():
            response.headers[header] = value
        
        return response
    
    def set_header(self, header_name, value):
        """
        Set or update a security header
        
        Args:
            header_name: Header name
            value: Header value
        """
        self.headers[header_name] = value
        logger.info(f"Security header set: {header_name}")
    
    def remove_header(self, header_name):
        """
        Remove a security header
        
        Args:
            header_name: Header name to remove
        """
        if header_name in self.headers:
            del self.headers[header_name]
            logger.info(f"Security header removed: {header_name}")
    
    def get_headers(self):
        """Get all configured security headers"""
        return self.headers.copy()


def get_security_header_recommendations():
    """
    Get security header recommendations
    
    Returns:
        Dictionary of recommended headers with explanations
    """
    return {
        'X-Content-Type-Options': {
            'value': 'nosniff',
            'purpose': 'Prevents MIME type sniffing',
            'protection': 'MIME confusion attacks'
        },
        'X-Frame-Options': {
            'value': 'DENY or SAMEORIGIN',
            'purpose': 'Prevents clickjacking',
            'protection': 'Clickjacking attacks'
        },
        'X-XSS-Protection': {
            'value': '1; mode=block',
            'purpose': 'Enables XSS filter in browsers',
            'protection': 'Cross-site scripting'
        },
        'Strict-Transport-Security': {
            'value': 'max-age=31536000; includeSubDomains',
            'purpose': 'Forces HTTPS connections',
            'protection': 'Man-in-the-middle attacks'
        },
        'Content-Security-Policy': {
            'value': "default-src 'self'",
            'purpose': 'Controls resource loading',
            'protection': 'XSS, data injection'
        },
        'Referrer-Policy': {
            'value': 'strict-origin-when-cross-origin',
            'purpose': 'Controls referrer information',
            'protection': 'Information leakage'
        },
        'Permissions-Policy': {
            'value': 'geolocation=(), microphone=(), camera=()',
            'purpose': 'Controls browser features',
            'protection': 'Unauthorized feature access'
        }
    }


def validate_security_headers(headers):
    """
    Validate if response has security headers
    
    Args:
        headers: Response headers dictionary
        
    Returns:
        Dictionary with validation results
    """
    recommendations = get_security_header_recommendations()
    results = {
        'total_headers': len(recommendations),
        'present': 0,
        'missing': [],
        'headers': {}
    }
    
    for header_name in recommendations.keys():
        if header_name in headers:
            results['present'] += 1
            results['headers'][header_name] = {
                'status': 'present',
                'value': headers[header_name]
            }
        else:
            results['missing'].append(header_name)
            results['headers'][header_name] = {
                'status': 'missing',
                'recommendation': recommendations[header_name]['value']
            }
    
    results['score'] = (results['present'] / results['total_headers']) * 100
    
    return results
