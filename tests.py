"""
Comprehensive Unit Tests for API Security Hardening
Tests rate limiting, brute force protection, threat detection, and security features
"""

import unittest
import time
from security.rate_limiter import RateLimiter, EndpointRateLimiter
from security.brute_force_protection import BruteForceProtection
from security.security_headers import SecurityHeaders, validate_security_headers
from threat_detection.threat_detector import ThreatDetector
from threat_detection.ip_blocker import IPBlocker
from validation.input_validator import InputValidator
from scanner.vulnerability_scanner import VulnerabilityScanner


class APISecurityTestCase(unittest.TestCase):
    """Unit tests for API Security Hardening"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test configuration"""
        print("\n" + "=" * 60)
        print("API Security Hardening - Unit Test Suite")
        print("=" * 60)
        print("Testing: Rate Limiting, Brute Force, Threat Detection")
        print("=" * 60 + "\n")
    
    # Test 1: Rate Limiting
    def test_01_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\n1. Testing rate limiting...")
        
        limiter = RateLimiter(max_requests=3, window=10)
        
        # First 3 requests should be allowed
        for i in range(3):
            allowed = limiter.is_allowed("192.168.1.100")
            self.assertTrue(allowed)
        
        print("   ✅ First 3 requests allowed")
        
        # 4th request should be blocked
        allowed = limiter.is_allowed("192.168.1.100")
        self.assertFalse(allowed)
        print("   ✅ 4th request blocked (rate limit exceeded)")
        
        # Check remaining
        remaining = limiter.get_remaining("192.168.1.100")
        self.assertEqual(remaining, 0)
        print(f"   ✅ Remaining requests: {remaining}")
    
    # Test 2: Brute Force Protection
    def test_02_brute_force_protection(self):
        """Test brute force protection"""
        print("\n2. Testing brute force protection...")
        
        protection = BruteForceProtection(max_attempts=3, lockout_duration=60)
        
        # Record failed attempts
        for i in range(3):
            locked = protection.record_failed_attempt("testuser", "192.168.1.100")
        
        # Account should be locked
        self.assertTrue(protection.is_locked("testuser"))
        print("   ✅ Account locked after 3 failed attempts")
        
        # Check remaining attempts
        remaining = protection.get_remaining_attempts("testuser")
        self.assertEqual(remaining, 0)
        print(f"   ✅ Remaining attempts: {remaining}")
        
        # Successful login should clear attempts
        protection.record_successful_attempt("testuser")
        protection.unlock_account("testuser")
        self.assertFalse(protection.is_locked("testuser"))
        print("   ✅ Account unlocked after successful login")
    
    # Test 3: Security Headers
    def test_03_security_headers(self):
        """Test security headers"""
        print("\n3. Testing security headers...")
        
        headers_manager = SecurityHeaders()
        headers = headers_manager.get_headers()
        
        # Check for important headers
        self.assertIn('X-Content-Type-Options', headers)
        self.assertIn('X-Frame-Options', headers)
        self.assertIn('X-XSS-Protection', headers)
        
        print(f"   ✅ {len(headers)} security headers configured")
        
        # Validate headers
        validation = validate_security_headers(headers)
        self.assertGreater(validation['score'], 0)
        print(f"   ✅ Security score: {validation['score']:.0f}%")
    
    # Test 4: SQL Injection Detection
    def test_04_sql_injection_detection(self):
        """Test SQL injection detection"""
        print("\n4. Testing SQL injection detection...")
        
        detector = ThreatDetector()
        
        # Safe input
        safe = "john_doe"
        self.assertFalse(detector.detect_sql_injection(safe))
        print(f"   ✅ Safe input passed: '{safe}'")
        
        # Malicious input
        malicious = "admin' OR '1'='1"
        self.assertTrue(detector.detect_sql_injection(malicious))
        print(f"   ✅ SQL injection detected: '{malicious}'")
        
        # Another malicious pattern
        malicious2 = "1; DROP TABLE users--"
        self.assertTrue(detector.detect_sql_injection(malicious2))
        print(f"   ✅ SQL injection detected: '{malicious2}'")
    
    # Test 5: XSS Detection
    def test_05_xss_detection(self):
        """Test XSS detection"""
        print("\n5. Testing XSS detection...")
        
        detector = ThreatDetector()
        
        # Safe input
        safe = "Hello World"
        self.assertFalse(detector.detect_xss(safe))
        print(f"   ✅ Safe input passed: '{safe}'")
        
        # Malicious input
        malicious = "<script>alert('xss')</script>"
        self.assertTrue(detector.detect_xss(malicious))
        print(f"   ✅ XSS detected: '{malicious}'")
        
        # Another XSS pattern
        malicious2 = "<img src=x onerror=alert('xss')>"
        self.assertTrue(detector.detect_xss(malicious2))
        print(f"   ✅ XSS detected: '{malicious2}'")
    
    # Test 6: IP Blocking
    def test_06_ip_blocking(self):
        """Test IP blocking functionality"""
        print("\n6. Testing IP blocking...")
        
        blocker = IPBlocker()
        
        # Block an IP
        blocker.block_ip("192.168.1.100", reason="Malicious activity")
        
        # Check if blocked
        self.assertTrue(blocker.is_blocked("192.168.1.100"))
        print("   ✅ IP blocked successfully")
        
        # Whitelist an IP
        blocker.whitelist_ip("192.168.1.1")
        self.assertFalse(blocker.is_blocked("192.168.1.1"))
        print("   ✅ IP whitelisted successfully")
        
        # Temporary block
        blocker.block_ip("192.168.1.200", reason="Suspicious", duration=2)
        self.assertTrue(blocker.is_blocked("192.168.1.200"))
        print("   ✅ Temporary block applied")
        
        # Wait for expiry
        time.sleep(2.5)
        self.assertFalse(blocker.is_blocked("192.168.1.200"))
        print("   ✅ Temporary block expired")
    
    # Test 7: Input Validation
    def test_07_input_validation(self):
        """Test input validation"""
        print("\n7. Testing input validation...")
        
        validator = InputValidator()
        
        # Email validation
        self.assertTrue(validator.validate_email("test@example.com"))
        self.assertFalse(validator.validate_email("invalid-email"))
        print("   ✅ Email validation working")
        
        # Username validation
        self.assertTrue(validator.validate_username("john_doe"))
        self.assertFalse(validator.validate_username("ab"))  # Too short
        print("   ✅ Username validation working")
        
        # Password validation
        result = validator.validate_password("StrongPass123")
        self.assertTrue(result['valid'])
        print("   ✅ Password validation working")
        
        # Sanitization
        dangerous = "<script>alert('xss')</script>"
        sanitized = validator.sanitize_string(dangerous)
        self.assertNotIn("<script>", sanitized)
        print(f"   ✅ Input sanitized: '{dangerous}' -> '{sanitized}'")
    
    # Test 8: Threat Detection in Dict
    def test_08_threat_detection_dict(self):
        """Test threat detection in dictionary data"""
        print("\n8. Testing threat detection in dict...")
        
        detector = ThreatDetector()
        
        # Safe data
        safe_data = {
            'username': 'john',
            'email': 'john@example.com'
        }
        
        threat = detector.detect_threats(safe_data)
        self.assertIsNone(threat)
        print("   ✅ Safe data passed")
        
        # Malicious data
        malicious_data = {
            'username': 'admin',
            'query': "SELECT * FROM users WHERE id=1"
        }
        
        threat = detector.detect_threats(malicious_data)
        self.assertIsNotNone(threat)
        print(f"   ✅ Threat detected: {threat}")
    
    # Test 9: Endpoint Rate Limiting
    def test_09_endpoint_rate_limiting(self):
        """Test endpoint-specific rate limiting"""
        print("\n9. Testing endpoint rate limiting...")
        
        limiter = EndpointRateLimiter()
        
        # Add different limits
        limiter.add_limit('/api/data', max_requests=10, window=60)
        limiter.add_limit('/auth/login', max_requests=3, window=60)
        
        # Test /auth/login limit
        for i in range(3):
            allowed = limiter.is_allowed('/auth/login', '192.168.1.100')
            self.assertTrue(allowed)
        
        # 4th request should be blocked
        allowed = limiter.is_allowed('/auth/login', '192.168.1.100')
        self.assertFalse(allowed)
        print("   ✅ Endpoint-specific limit enforced")
        
        # /api/data should still allow requests
        allowed = limiter.is_allowed('/api/data', '192.168.1.100')
        self.assertTrue(allowed)
        print("   ✅ Different endpoints have independent limits")
    
    # Test 10: Security Middleware Integration
    def test_10_security_middleware_integration(self):
        """Test security middleware components working together"""
        print("\n10. Testing security middleware integration...")
        
        # Initialize all components
        rate_limiter = RateLimiter(max_requests=5, window=10)
        brute_force = BruteForceProtection(max_attempts=3)
        threat_detector = ThreatDetector()
        ip_blocker = IPBlocker()
        
        # Test rate limiting
        for i in range(5):
            rate_limiter.is_allowed("192.168.1.100")
        
        self.assertFalse(rate_limiter.is_allowed("192.168.1.100"))
        print("   ✅ Rate limiter working")
        
        # Test brute force
        for i in range(3):
            brute_force.record_failed_attempt("user", "192.168.1.100")
        
        self.assertTrue(brute_force.is_locked("user"))
        print("   ✅ Brute force protection working")
        
        # Test threat detection
        threat = threat_detector.detect_threats("SELECT * FROM users")
        self.assertIsNotNone(threat)
        print(f"   ✅ Threat detector working: {threat}")
        
        # Test IP blocking
        ip_blocker.block_ip("192.168.1.100")
        self.assertTrue(ip_blocker.is_blocked("192.168.1.100"))
        print("   ✅ IP blocker working")
        
        print("   ✅ All security components integrated successfully")


def run_tests():
    """Run all unit tests"""
    # Create test suite
    test_suite = unittest.TestLoader().loadTestsFromTestCase(APISecurityTestCase)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    
    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\n💥 ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    if not result.failures and not result.errors:
        print("\n🎉 ALL TESTS PASSED! 🎉")
    
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("API Security Hardening - Unit Test Suite")
    print("=" * 60)
    
    try:
        success = run_tests()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
