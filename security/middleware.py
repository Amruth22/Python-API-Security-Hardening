"""
Security Middleware
Custom security middleware for API protection
"""

import logging
from flask import request, jsonify, g
from functools import wraps

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """
    Security middleware for Flask
    Provides authentication, rate limiting, and threat detection
    """
    
    def __init__(self, app, api_key, rate_limiter, brute_force_protection, threat_detector):
        """
        Initialize security middleware
        
        Args:
            app: Flask app
            api_key: Valid API key
            rate_limiter: RateLimiter instance
            brute_force_protection: BruteForceProtection instance
            threat_detector: ThreatDetector instance
        """
        self.app = app
        self.api_key = api_key
        self.rate_limiter = rate_limiter
        self.brute_force_protection = brute_force_protection
        self.threat_detector = threat_detector
        
        # Register middleware
        self.app.before_request(self.before_request_handler)
        
        logger.info("Security Middleware initialized")
    
    def before_request_handler(self):
        """Handle security checks before each request"""
        # Skip security for certain paths
        if request.path in ['/', '/health', '/security/info']:
            return None
        
        # Get client IP
        client_ip = request.remote_addr
        g.client_ip = client_ip
        
        # Check rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return jsonify({
                'error': 'Rate limit exceeded',
                'message': 'Too many requests. Please try again later.',
                'retry_after': int(self.rate_limiter.get_reset_time(client_ip))
            }), 429
        
        # Check if IP is suspicious
        if self.brute_force_protection.is_ip_suspicious(client_ip):
            logger.warning(f"Suspicious IP detected: {client_ip}")
            return jsonify({
                'error': 'Suspicious activity detected',
                'message': 'Your IP has been flagged for suspicious activity'
            }), 403
        
        # Validate input for threats
        if request.is_json:
            data = request.get_json()
            if data:
                threat = self.threat_detector.detect_threats(data)
                if threat:
                    logger.warning(f"Threat detected from {client_ip}: {threat}")
                    return jsonify({
                        'error': 'Security threat detected',
                        'message': f'Potential {threat} detected in request'
                    }), 400
        
        return None


def require_api_key(f):
    """
    Decorator to require API key authentication
    
    Usage:
        @app.route('/protected')
        @require_api_key
        def protected_endpoint():
            return {'data': 'secret'}
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            logger.warning(f"Missing API key from {request.remote_addr}")
            return jsonify({
                'error': 'Unauthorized',
                'message': 'API key required'
            }), 401
        
        # Get expected API key from app config
        expected_key = request.environ.get('API_KEY')
        
        if api_key != expected_key:
            logger.warning(f"Invalid API key from {request.remote_addr}")
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid API key'
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


def sanitize_input(f):
    """
    Decorator to sanitize input data
    
    Usage:
        @app.route('/api/data', methods=['POST'])
        @sanitize_input
        def create_data():
            data = request.get_json()
            # data is now sanitized
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.is_json:
            data = request.get_json()
            
            # Sanitize strings
            sanitized = {}
            for key, value in data.items():
                if isinstance(value, str):
                    # Remove potentially dangerous characters
                    sanitized[key] = value.replace('<', '').replace('>', '').replace('"', '').strip()
                else:
                    sanitized[key] = value
            
            # Replace request data
            request.get_json = lambda: sanitized
        
        return f(*args, **kwargs)
    
    return decorated_function


class IPWhitelist:
    """
    IP whitelist for restricting access
    """
    
    def __init__(self, allowed_ips=None):
        """
        Initialize IP whitelist
        
        Args:
            allowed_ips: List of allowed IP addresses
        """
        self.allowed_ips = set(allowed_ips or [])
        logger.info(f"IP Whitelist initialized with {len(self.allowed_ips)} IPs")
    
    def is_allowed(self, ip):
        """Check if IP is whitelisted"""
        return ip in self.allowed_ips or not self.allowed_ips
    
    def add_ip(self, ip):
        """Add IP to whitelist"""
        self.allowed_ips.add(ip)
        logger.info(f"IP added to whitelist: {ip}")
    
    def remove_ip(self, ip):
        """Remove IP from whitelist"""
        if ip in self.allowed_ips:
            self.allowed_ips.remove(ip)
            logger.info(f"IP removed from whitelist: {ip}")


class IPBlacklist:
    """
    IP blacklist for blocking malicious IPs
    """
    
    def __init__(self):
        """Initialize IP blacklist"""
        self.blocked_ips = set()
        logger.info("IP Blacklist initialized")
    
    def is_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def block_ip(self, ip, reason=""):
        """
        Block an IP address
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
        """
        self.blocked_ips.add(ip)
        logger.warning(f"IP blocked: {ip} - Reason: {reason}")
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            logger.info(f"IP unblocked: {ip}")
    
    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
