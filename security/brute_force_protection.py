"""
Brute Force Protection
Prevents brute force attacks on login endpoints
"""

import time
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class BruteForceProtection:
    """
    Brute force protection system
    Tracks failed login attempts and locks accounts
    """
    
    def __init__(self, max_attempts=5, lockout_duration=300, window=60):
        """
        Initialize brute force protection
        
        Args:
            max_attempts: Max failed attempts before lockout
            lockout_duration: Lockout duration in seconds
            window: Time window for counting attempts
        """
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.window = window
        
        self.failed_attempts = defaultdict(list)  # {username: [timestamps]}
        self.locked_accounts = {}  # {username: lock_time}
        self.blocked_ips = defaultdict(list)  # {ip: [timestamps]}
        
        logger.info(f"Brute Force Protection initialized: {max_attempts} attempts, {lockout_duration}s lockout")
    
    def is_locked(self, username):
        """
        Check if account is locked
        
        Args:
            username: Username to check
            
        Returns:
            True if locked, False otherwise
        """
        if username not in self.locked_accounts:
            return False
        
        lock_time = self.locked_accounts[username]
        current_time = time.time()
        
        # Check if lockout has expired
        if current_time - lock_time >= self.lockout_duration:
            # Unlock account
            del self.locked_accounts[username]
            self.failed_attempts[username].clear()
            logger.info(f"Account {username} unlocked after timeout")
            return False
        
        return True
    
    def record_failed_attempt(self, username, ip):
        """
        Record a failed login attempt
        
        Args:
            username: Username that failed
            ip: IP address of attempt
        """
        current_time = time.time()
        
        # Clean old attempts
        self.failed_attempts[username] = [
            t for t in self.failed_attempts[username]
            if current_time - t < self.window
        ]
        
        # Add current attempt
        self.failed_attempts[username].append(current_time)
        
        # Also track by IP
        self.blocked_ips[ip].append(current_time)
        
        # Check if should lock
        if len(self.failed_attempts[username]) >= self.max_attempts:
            self.locked_accounts[username] = current_time
            logger.warning(f"Account {username} locked after {self.max_attempts} failed attempts")
            return True
        
        logger.info(f"Failed login attempt for {username} from {ip} ({len(self.failed_attempts[username])}/{self.max_attempts})")
        return False
    
    def record_successful_attempt(self, username):
        """
        Record successful login (clears failed attempts)
        
        Args:
            username: Username that succeeded
        """
        if username in self.failed_attempts:
            self.failed_attempts[username].clear()
        
        logger.info(f"Successful login for {username}, attempts cleared")
    
    def is_ip_suspicious(self, ip):
        """
        Check if IP has too many failed attempts
        
        Args:
            ip: IP address to check
            
        Returns:
            True if suspicious, False otherwise
        """
        current_time = time.time()
        
        # Clean old attempts
        self.blocked_ips[ip] = [
            t for t in self.blocked_ips[ip]
            if current_time - t < self.window
        ]
        
        # Check if too many attempts from this IP
        return len(self.blocked_ips[ip]) >= self.max_attempts * 2
    
    def get_remaining_attempts(self, username):
        """
        Get remaining login attempts before lockout
        
        Args:
            username: Username to check
            
        Returns:
            Number of remaining attempts
        """
        current_time = time.time()
        
        # Clean old attempts
        self.failed_attempts[username] = [
            t for t in self.failed_attempts[username]
            if current_time - t < self.window
        ]
        
        used = len(self.failed_attempts[username])
        remaining = max(0, self.max_attempts - used)
        
        return remaining
    
    def get_lockout_time_remaining(self, username):
        """
        Get remaining lockout time
        
        Args:
            username: Username to check
            
        Returns:
            Seconds remaining in lockout, or 0 if not locked
        """
        if username not in self.locked_accounts:
            return 0
        
        lock_time = self.locked_accounts[username]
        current_time = time.time()
        elapsed = current_time - lock_time
        
        remaining = max(0, self.lockout_duration - elapsed)
        return remaining
    
    def unlock_account(self, username):
        """
        Manually unlock an account
        
        Args:
            username: Username to unlock
        """
        if username in self.locked_accounts:
            del self.locked_accounts[username]
        
        if username in self.failed_attempts:
            self.failed_attempts[username].clear()
        
        logger.info(f"Account {username} manually unlocked")
    
    def get_stats(self):
        """Get brute force protection statistics"""
        return {
            'locked_accounts': len(self.locked_accounts),
            'tracked_usernames': len(self.failed_attempts),
            'suspicious_ips': sum(1 for ip in self.blocked_ips if self.is_ip_suspicious(ip)),
            'max_attempts': self.max_attempts,
            'lockout_duration': self.lockout_duration
        }
