"""
API Security Hardening - Main Demonstration
Shows examples of all security features
"""

import time
from security.rate_limiter import RateLimiter, EndpointRateLimiter
from security.brute_force_protection import BruteForceProtection
from security.security_headers import SecurityHeaders, validate_security_headers
from threat_detection.threat_detector import ThreatDetector
from threat_detection.ip_blocker import IPBlocker
from validation.input_validator import InputValidator
from scanner.vulnerability_scanner import VulnerabilityScanner


def print_section(title):
    """Print section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_rate_limiting():
    """Demonstrate rate limiting"""
    print_section("1. Rate Limiting - API Abuse Prevention")
    
    limiter = RateLimiter(max_requests=5, window=10)
    
    print("\n[STATS] Rate Limit: 5 requests per 10 seconds")
    print("\nSimulating 7 requests from same IP:")
    
    for i in range(7):
        allowed = limiter.is_allowed("192.168.1.100")
        remaining = limiter.get_remaining("192.168.1.100")
        
        if allowed:
            print(f"   Request {i+1}: [PASS] Allowed (Remaining: {remaining})")
        else:
            print(f"   Request {i+1}: [FAIL] Blocked (Rate limit exceeded)")


def demo_brute_force_protection():
    """Demonstrate brute force protection"""
    print_section("2. Brute Force Protection - Login Security")
    
    protection = BruteForceProtection(max_attempts=3, lockout_duration=60)
    
    print("\n[LOCK] Max login attempts: 3")
    print("\nSimulating failed login attempts:")
    
    for i in range(5):
        if protection.is_locked("john_doe"):
            remaining = protection.get_lockout_time_remaining("john_doe")
            print(f"   Attempt {i+1}: [FAIL] Account locked ({remaining:.0f}s remaining)")
        else:
            locked = protection.record_failed_attempt("john_doe", "192.168.1.100")
            remaining_attempts = protection.get_remaining_attempts("john_doe")
            
            if locked:
                print(f"   Attempt {i+1}: [LOCK] Account LOCKED!")
            else:
                print(f"   Attempt {i+1}: [FAIL] Failed (Remaining: {remaining_attempts})")


def demo_security_headers():
    """Demonstrate security headers"""
    print_section("3. Security Headers - HTTP Hardening")
    
    headers_manager = SecurityHeaders()
    headers = headers_manager.get_headers()
    
    print("\n[SHIELD]  Configured Security Headers:")
    for header, value in headers.items():
        print(f"   {header}: {value[:50]}...")


def demo_threat_detection():
    """Demonstrate threat detection"""
    print_section("4. Threat Detection - Attack Prevention")
    
    detector = ThreatDetector()
    
    # Test SQL injection
    print("\n[SEARCH] Testing SQL Injection Detection:")
    
    safe_input = "john_doe"
    malicious_input = "admin' OR '1'='1"
    
    print(f"   Safe input: '{safe_input}'")
    print(f"   Result: {'[FAIL] Threat!' if detector.detect_sql_injection(safe_input) else '[PASS] Safe'}")
    
    print(f"\n   Malicious input: '{malicious_input}'")
    print(f"   Result: {'[FAIL] Threat Detected!' if detector.detect_sql_injection(malicious_input) else '[PASS] Safe'}")
    
    # Test XSS
    print("\n[SEARCH] Testing XSS Detection:")
    
    safe_html = "Hello World"
    malicious_html = "<script>alert('xss')</script>"
    
    print(f"   Safe HTML: '{safe_html}'")
    print(f"   Result: {'[FAIL] Threat!' if detector.detect_xss(safe_html) else '[PASS] Safe'}")
    
    print(f"\n   Malicious HTML: '{malicious_html}'")
    print(f"   Result: {'[FAIL] Threat Detected!' if detector.detect_xss(malicious_html) else '[PASS] Safe'}")


def demo_ip_blocking():
    """Demonstrate IP blocking"""
    print_section("5. IP Blocking - Malicious IP Management")
    
    blocker = IPBlocker()
    
    # Block an IP
    print("\n[DENIED] Blocking malicious IP:")
    blocker.block_ip("192.168.1.100", reason="Multiple failed login attempts")
    print(f"   IP 192.168.1.100 blocked")
    
    # Check if blocked
    is_blocked = blocker.is_blocked("192.168.1.100")
    print(f"   Is blocked: {is_blocked}")
    
    # Whitelist an IP
    print("\n[PASS] Whitelisting trusted IP:")
    blocker.whitelist_ip("192.168.1.1")
    print(f"   IP 192.168.1.1 whitelisted")
    
    # Get stats
    stats = blocker.get_stats()
    print(f"\n[STATS] IP Blocker Stats:")
    print(f"   Blacklisted: {stats['blacklist_size']}")
    print(f"   Whitelisted: {stats['whitelist_size']}")


def demo_input_validation():
    """Demonstrate input validation"""
    print_section("6. Input Validation - Data Sanitization")
    
    validator = InputValidator()
    
    # Email validation
    print("\n[EMAIL] Email Validation:")
    emails = ["valid@example.com", "invalid-email", "test@test"]
    
    for email in emails:
        valid = validator.validate_email(email)
        print(f"   {email}: {'[PASS] Valid' if valid else '[FAIL] Invalid'}")
    
    # Password validation
    print("\n[KEY] Password Validation:")
    passwords = ["weak", "StrongPass123", "nodigits"]
    
    for pwd in passwords:
        result = validator.validate_password(pwd)
        if result['valid']:
            print(f"   '{pwd}': [PASS] Valid")
        else:
            print(f"   '{pwd}': [FAIL] Invalid - {result['errors'][0]}")
    
    # Input sanitization
    print("\n[EMOJI] Input Sanitization:")
    dangerous_input = "<script>alert('xss')</script>"
    sanitized = validator.sanitize_string(dangerous_input)
    print(f"   Original: {dangerous_input}")
    print(f"   Sanitized: {sanitized}")


def demo_vulnerability_scanner():
    """Demonstrate vulnerability scanning"""
    print_section("7. Vulnerability Scanner - Security Audit")
    
    scanner = VulnerabilityScanner()
    
    print("\n[SEARCH] Scanning for vulnerabilities...")
    print("   (This is a demonstration - actual scanning requires running API)")
    
    # Simulate findings
    vulnerabilities = [
        {
            'type': 'Missing Security Header',
            'severity': 'Medium',
            'header': 'X-Frame-Options',
            'recommendation': 'Add X-Frame-Options: DENY'
        },
        {
            'type': 'Weak Password Policy',
            'severity': 'High',
            'description': 'Password requirements too weak',
            'recommendation': 'Enforce stronger password policy'
        }
    ]
    
    report = scanner.generate_report(vulnerabilities)
    scanner.print_report(report)


def demo_endpoint_rate_limiting():
    """Demonstrate endpoint-specific rate limiting"""
    print_section("8. Endpoint-Specific Rate Limiting")
    
    limiter = EndpointRateLimiter()
    
    # Different limits for different endpoints
    limiter.add_limit('/api/data', max_requests=100, window=60)
    limiter.add_limit('/auth/login', max_requests=5, window=60)
    limiter.add_limit('/api/upload', max_requests=10, window=60)
    
    print("\n[STATS] Endpoint Rate Limits:")
    print("   /api/data: 100 requests/minute")
    print("   /auth/login: 5 requests/minute")
    print("   /api/upload: 10 requests/minute")
    
    # Test
    print("\n[SEARCH] Testing /auth/login endpoint:")
    for i in range(7):
        allowed = limiter.is_allowed('/auth/login', '192.168.1.100')
        remaining = limiter.get_remaining('/auth/login', '192.168.1.100')
        
        if allowed:
            print(f"   Request {i+1}: [PASS] Allowed (Remaining: {remaining})")
        else:
            print(f"   Request {i+1}: [FAIL] Blocked")


def main():
    """Run all demonstrations"""
    print("\n" + "=" * 70)
    print("  API Security Hardening - Demonstration")
    print("=" * 70)
    
    try:
        demo_rate_limiting()
        demo_brute_force_protection()
        demo_security_headers()
        demo_threat_detection()
        demo_ip_blocking()
        demo_input_validation()
        demo_vulnerability_scanner()
        demo_endpoint_rate_limiting()
        
        print("\n" + "=" * 70)
        print("  All Demonstrations Completed!")
        print("=" * 70)
        print("\nKey Security Features Demonstrated:")
        print("  1. Rate Limiting - Prevent API abuse")
        print("  2. Brute Force Protection - Secure login")
        print("  3. Security Headers - HTTP hardening")
        print("  4. Threat Detection - SQL injection, XSS")
        print("  5. IP Blocking - Block malicious IPs")
        print("  6. Input Validation - Sanitize data")
        print("  7. Vulnerability Scanning - Find issues")
        print("  8. Endpoint Rate Limiting - Granular control")
        print("\nTo run Flask API:")
        print("  python api/app.py")
        print("\nTo run tests:")
        print("  python tests.py")
        print()
        
    except Exception as e:
        print(f"\n[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
