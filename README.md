# API Security Hardening

Educational Python application demonstrating **API security hardening**, **threat detection**, **custom security middleware**, **brute force protection**, **API abuse prevention**, **security headers**, and **vulnerability scanning**.

## Features

### 🛡️ API Security Hardening
- **Input Validation** - Sanitize and validate user input
- **Authentication** - API key validation
- **Authorization** - Role-based access control
- **Security Middleware** - Layered security approach
- **HTTPS Enforcement** - Secure connections

### 🔍 Threat Detection
- **SQL Injection Detection** - Pattern-based detection
- **XSS Detection** - Cross-site scripting prevention
- **Path Traversal Detection** - Directory traversal prevention
- **Malicious Pattern Recognition** - Common attack patterns
- **Threat Logging** - Security event tracking

### 🚦 Rate Limiting
- **Global Rate Limiting** - Overall request limits
- **Endpoint-Specific Limits** - Different limits per endpoint
- **IP-Based Limiting** - Per-IP rate limits
- **Sliding Window** - Time-based request tracking
- **Rate Limit Headers** - X-RateLimit-* headers

### 🔒 Brute Force Protection
- **Login Attempt Tracking** - Count failed logins
- **Account Lockout** - Lock after N failures
- **IP-Based Blocking** - Block suspicious IPs
- **Lockout Duration** - Configurable timeout
- **Automatic Unlock** - Time-based unlock

### 🚫 IP Blocking
- **Blacklist Management** - Block malicious IPs
- **Whitelist Management** - Allow trusted IPs
- **Temporary Blocks** - Time-limited blocks
- **Block History** - Track blocking events
- **Auto-Expiry** - Temporary blocks expire

### 📋 Security Headers
- **X-Content-Type-Options** - Prevent MIME sniffing
- **X-Frame-Options** - Prevent clickjacking
- **X-XSS-Protection** - XSS filter
- **Strict-Transport-Security** - Force HTTPS
- **Content-Security-Policy** - CSP rules
- **Referrer-Policy** - Control referrer info

### 🔎 Vulnerability Scanning
- **Header Scanner** - Check security headers
- **Injection Scanner** - Test for SQL injection
- **XSS Scanner** - Test for XSS vulnerabilities
- **Authentication Scanner** - Check auth requirements
- **Security Report** - Generate findings

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/Amruth22/Python-API-Security-Hardening.git
cd Python-API-Security-Hardening
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Demonstrations
```bash
python main.py
```

### 5. Run Flask API
```bash
python api/app.py
```

The API will be available at `http://localhost:5000`

### 6. Run Tests
```bash
python tests.py
```

## Project Structure

```
Python-API-Security-Hardening/
│
├── security/
│   ├── rate_limiter.py          # Rate limiting
│   ├── brute_force_protection.py # Login protection
│   ├── security_headers.py      # HTTP headers
│   └── middleware.py            # Security middleware
│
├── threat_detection/
│   ├── threat_detector.py       # Threat detection
│   └── ip_blocker.py            # IP blocking
│
├── validation/
│   └── input_validator.py       # Input validation
│
├── scanner/
│   └── vulnerability_scanner.py # Security scanning
│
├── api/
│   └── app.py                   # Flask API
│
├── main.py                      # Demonstration script
├── tests.py                     # 10 unit tests
├── requirements.txt             # Dependencies
├── .env                         # Configuration
└── README.md                    # This file
```

## Usage Examples

### Rate Limiting

```python
from security.rate_limiter import RateLimiter

# Create rate limiter
limiter = RateLimiter(max_requests=100, window=60)

# Check if request is allowed
if limiter.is_allowed(client_ip):
    # Process request
    pass
else:
    # Return 429 Too Many Requests
    return "Rate limit exceeded", 429
```

### Brute Force Protection

```python
from security.brute_force_protection import BruteForceProtection

# Create protection
protection = BruteForceProtection(max_attempts=5, lockout_duration=300)

# Check if account is locked
if protection.is_locked(username):
    return "Account locked", 423

# Record failed login
locked = protection.record_failed_attempt(username, client_ip)

if locked:
    return "Account locked due to too many failures", 423
```

### Threat Detection

```python
from threat_detection.threat_detector import ThreatDetector

# Create detector
detector = ThreatDetector()

# Check for SQL injection
if detector.detect_sql_injection(user_input):
    return "SQL injection detected", 400

# Check for XSS
if detector.detect_xss(user_input):
    return "XSS detected", 400

# Detect any threat
threat = detector.detect_threats(request_data)
if threat:
    return f"{threat} detected", 400
```

### Security Headers

```python
from security.security_headers import SecurityHeaders

# Add to Flask app
app = Flask(__name__)
security_headers = SecurityHeaders(app)

# All responses will include security headers
```

### IP Blocking

```python
from threat_detection.ip_blocker import IPBlocker

# Create blocker
blocker = IPBlocker()

# Block an IP
blocker.block_ip("192.168.1.100", reason="Malicious activity")

# Check if blocked
if blocker.is_blocked(client_ip):
    return "IP blocked", 403

# Whitelist an IP
blocker.whitelist_ip("192.168.1.1")
```

### Input Validation

```python
from validation.input_validator import InputValidator

# Create validator
validator = InputValidator()

# Validate email
if not validator.validate_email(email):
    return "Invalid email", 400

# Validate password
result = validator.validate_password(password)
if not result['valid']:
    return {"errors": result['errors']}, 400

# Sanitize input
sanitized = validator.sanitize_dict(request_data)
```

## API Endpoints

### Public Endpoints

#### Get API Info
```http
GET /
```

#### Health Check
```http
GET /health
```

### Authentication

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "Admin123!"
}
```

**Brute Force Protection:**
- Max 5 attempts per account
- 5-minute lockout after failures
- IP tracking for suspicious activity

### Protected Endpoints

#### Get Data (Requires API Key)
```http
GET /api/data
X-API-Key: secure-api-key-12345
```

#### Create User (Requires API Key)
```http
POST /api/user
X-API-Key: secure-api-key-12345
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

### Security Endpoints

#### Get Security Info
```http
GET /security/info
```

#### Get Security Headers
```http
GET /security/headers
```

#### Scan Endpoint (Requires API Key)
```http
POST /security/scan
X-API-Key: secure-api-key-12345
Content-Type: application/json

{
  "url": "http://localhost:5000/api/data"
}
```

## Security Features Explained

### 1. Rate Limiting

**Purpose:** Prevent API abuse and DDoS attacks

**How it works:**
- Tracks requests per IP address
- Sliding time window
- Returns 429 when limit exceeded
- Includes retry-after header

**Configuration:**
```python
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

### 2. Brute Force Protection

**Purpose:** Prevent password guessing attacks

**How it works:**
- Tracks failed login attempts
- Locks account after threshold
- Blocks suspicious IPs
- Auto-unlocks after timeout

**Configuration:**
```python
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=300
```

### 3. Security Headers

**Headers Added:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Content-Security-Policy: default-src 'self'`

### 4. Threat Detection

**Detects:**
- SQL injection attempts
- XSS attacks
- Path traversal
- Malicious patterns

**Action:**
- Blocks request
- Logs security event
- Returns 400 Bad Request

### 5. Input Validation

**Validates:**
- Email format
- Username format
- Password strength
- JSON structure
- Data types

**Sanitizes:**
- HTML escaping
- Special character removal
- Whitespace trimming

## Testing

Run the comprehensive test suite:

```bash
python tests.py
```

### Test Coverage (10 Tests)

1. ✅ **Rate Limiting** - Test request limits
2. ✅ **Brute Force Protection** - Test login lockout
3. ✅ **Security Headers** - Test header presence
4. ✅ **SQL Injection Detection** - Test SQL patterns
5. ✅ **XSS Detection** - Test XSS patterns
6. ✅ **IP Blocking** - Test blacklist/whitelist
7. ✅ **Input Validation** - Test validation rules
8. ✅ **Threat Detection Dict** - Test nested data
9. ✅ **Endpoint Rate Limiting** - Test per-endpoint limits
10. ✅ **Security Integration** - Test all components together

## Common Security Threats

### SQL Injection
```
Malicious: admin' OR '1'='1
Detection: Pattern matching for SQL keywords
Prevention: Input validation, parameterized queries
```

### XSS (Cross-Site Scripting)
```
Malicious: <script>alert('xss')</script>
Detection: Pattern matching for script tags
Prevention: HTML escaping, CSP headers
```

### Brute Force
```
Attack: Multiple login attempts
Detection: Failed attempt counting
Prevention: Account lockout, rate limiting
```

### API Abuse
```
Attack: Excessive requests
Detection: Request rate tracking
Prevention: Rate limiting, throttling
```

## Production Considerations

For production use:

1. **Use HTTPS:**
   - Always use SSL/TLS
   - Enforce HTTPS
   - Use valid certificates

2. **External WAF:**
   - Use cloud WAF (Cloudflare, AWS WAF)
   - DDoS protection
   - Advanced threat detection

3. **Database Security:**
   - Use parameterized queries
   - Encrypt sensitive data
   - Implement proper access control

4. **Monitoring:**
   - Log security events
   - Set up alerts
   - Monitor attack patterns

5. **Regular Updates:**
   - Keep dependencies updated
   - Patch vulnerabilities
   - Security audits

## Dependencies

- **Flask 3.0.0** - Web framework
- **requests 2.31.0** - HTTP client
- **python-dotenv 1.0.0** - Environment variables
- **pytest 7.4.3** - Testing framework
- **passlib 1.7.4** - Password hashing

## License

This project is for educational purposes. Feel free to use and modify as needed.

---

**Happy Securing! 🔒**
