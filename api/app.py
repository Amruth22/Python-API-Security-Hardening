"""
Flask API with Security Hardening
Demonstrates all security features
"""

from flask import Flask, request, jsonify
import logging
import os

from security.rate_limiter import RateLimiter
from security.brute_force_protection import BruteForceProtection
from security.security_headers import SecurityHeaders
from security.middleware import SecurityMiddleware, require_api_key
from threat_detection.threat_detector import ThreatDetector
from threat_detection.ip_blocker import IPBlocker
from validation.input_validator import InputValidator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Load configuration
API_KEY = os.getenv('API_KEY', 'secure-api-key-12345')
app.config['API_KEY'] = API_KEY

# Initialize security components
rate_limiter = RateLimiter(max_requests=100, window=60)
brute_force_protection = BruteForceProtection(max_attempts=5, lockout_duration=300)
threat_detector = ThreatDetector()
ip_blocker = IPBlocker()
input_validator = InputValidator()

# Add security headers
security_headers = SecurityHeaders(app)

# Add security middleware
security_middleware = SecurityMiddleware(
    app, API_KEY, rate_limiter, brute_force_protection, threat_detector
)

# In-memory user storage
users_db = {
    'admin': {'password': 'Admin123!', 'role': 'admin'},
    'user1': {'password': 'User123!', 'role': 'user'}
}


@app.route('/')
def index():
    """Root endpoint"""
    return jsonify({
        'message': 'API Security Hardening Demo',
        'version': '1.0.0',
        'security_features': [
            'Rate Limiting',
            'Brute Force Protection',
            'Threat Detection',
            'Security Headers',
            'IP Blocking',
            'Input Validation'
        ],
        'endpoints': {
            'login': '/auth/login',
            'protected': '/api/data',
            'security_info': '/security/info',
            'health': '/health'
        }
    })


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})


@app.route('/security/info')
def security_info():
    """Get security configuration info"""
    return jsonify({
        'rate_limiting': rate_limiter.get_stats(),
        'brute_force_protection': brute_force_protection.get_stats(),
        'ip_blocker': ip_blocker.get_stats(),
        'threat_detector': threat_detector.get_threat_stats()
    })


@app.route('/auth/login', methods=['POST'])
def login():
    """Login endpoint with brute force protection"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({
            'error': 'Bad Request',
            'message': 'Username and password required'
        }), 400
    
    username = data['username']
    password = data['password']
    client_ip = request.remote_addr
    
    # Check if account is locked
    if brute_force_protection.is_locked(username):
        remaining = brute_force_protection.get_lockout_time_remaining(username)
        return jsonify({
            'error': 'Account Locked',
            'message': f'Account locked due to too many failed attempts',
            'retry_after': int(remaining)
        }), 423
    
    # Validate credentials
    if username in users_db and users_db[username]['password'] == password:
        # Successful login
        brute_force_protection.record_successful_attempt(username)
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'username': username,
            'role': users_db[username]['role']
        })
    else:
        # Failed login
        locked = brute_force_protection.record_failed_attempt(username, client_ip)
        remaining = brute_force_protection.get_remaining_attempts(username)
        
        if locked:
            return jsonify({
                'error': 'Account Locked',
                'message': 'Too many failed attempts. Account locked.',
                'retry_after': brute_force_protection.lockout_duration
            }), 423
        else:
            return jsonify({
                'error': 'Invalid Credentials',
                'message': 'Invalid username or password',
                'remaining_attempts': remaining
            }), 401


@app.route('/api/data', methods=['GET'])
@require_api_key
def get_data():
    """Protected endpoint requiring API key"""
    return jsonify({
        'status': 'success',
        'data': 'This is protected data',
        'message': 'You have valid API key'
    })


@app.route('/api/user', methods=['POST'])
@require_api_key
def create_user():
    """Create user with input validation"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Validate required fields
    validation = input_validator.validate_json_structure(data, ['username', 'email', 'password'])
    
    if not validation['valid']:
        return jsonify({
            'error': 'Validation Failed',
            'errors': validation['errors']
        }), 400
    
    # Validate email
    if not input_validator.validate_email(data['email']):
        return jsonify({
            'error': 'Invalid Email',
            'message': 'Email format is invalid'
        }), 400
    
    # Validate username
    if not input_validator.validate_username(data['username']):
        return jsonify({
            'error': 'Invalid Username',
            'message': 'Username must be 3-20 characters, alphanumeric'
        }), 400
    
    # Validate password
    password_validation = input_validator.validate_password(data['password'])
    if not password_validation['valid']:
        return jsonify({
            'error': 'Weak Password',
            'errors': password_validation['errors']
        }), 400
    
    # Sanitize input
    sanitized_data = input_validator.sanitize_dict(data)
    
    return jsonify({
        'status': 'success',
        'message': 'User created successfully',
        'user': {
            'username': sanitized_data['username'],
            'email': sanitized_data['email']
        }
    }), 201


@app.route('/security/scan', methods=['POST'])
@require_api_key
def scan_endpoint():
    """Scan an endpoint for vulnerabilities"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL required'}), 400
    
    from scanner.vulnerability_scanner import VulnerabilityScanner
    
    scanner = VulnerabilityScanner()
    vulnerabilities = scanner.scan_endpoint(data['url'])
    report = scanner.generate_report(vulnerabilities)
    
    return jsonify(report)


@app.route('/security/headers', methods=['GET'])
def get_security_headers():
    """Get configured security headers"""
    headers = security_headers.get_headers()
    
    return jsonify({
        'headers': headers,
        'count': len(headers)
    })


if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('DEBUG', 'True').lower() == 'true'
    
    print("=" * 60)
    print("API Security Hardening - Flask API")
    print("=" * 60)
    print(f"Starting on port {port}")
    print("Security features enabled:")
    print("  - Rate Limiting")
    print("  - Brute Force Protection")
    print("  - Threat Detection")
    print("  - Security Headers")
    print("  - Input Validation")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
