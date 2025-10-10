"""
Rate Limiter
Prevents API abuse by limiting request rates
"""

import time
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter to prevent API abuse
    Tracks requests per IP address
    """
    
    def __init__(self, max_requests=100, window=60):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum requests allowed in window
            window: Time window in seconds
        """
        self.max_requests = max_requests
        self.window = window
        self.requests = defaultdict(list)
        
        logger.info(f"Rate Limiter initialized: {max_requests} requests per {window}s")
    
    def is_allowed(self, identifier):
        """
        Check if request is allowed
        
        Args:
            identifier: IP address or user identifier
            
        Returns:
            True if allowed, False if rate limit exceeded
        """
        current_time = time.time()
        
        # Clean old requests outside window
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < self.window
        ]
        
        # Check if under limit
        if len(self.requests[identifier]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for {identifier}")
            return False
        
        # Add current request
        self.requests[identifier].append(current_time)
        return True
    
    def get_remaining(self, identifier):
        """Get remaining requests for identifier"""
        current_time = time.time()
        
        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < self.window
        ]
        
        used = len(self.requests[identifier])
        remaining = max(0, self.max_requests - used)
        
        return remaining
    
    def get_reset_time(self, identifier):
        """Get time until rate limit resets"""
        if not self.requests[identifier]:
            return 0
        
        oldest_request = min(self.requests[identifier])
        reset_time = oldest_request + self.window
        current_time = time.time()
        
        return max(0, reset_time - current_time)
    
    def reset(self, identifier):
        """Reset rate limit for identifier"""
        if identifier in self.requests:
            del self.requests[identifier]
            logger.info(f"Rate limit reset for {identifier}")
    
    def get_stats(self):
        """Get rate limiter statistics"""
        return {
            'total_tracked_ips': len(self.requests),
            'max_requests': self.max_requests,
            'window_seconds': self.window,
            'active_limiters': sum(1 for reqs in self.requests.values() if reqs)
        }


class EndpointRateLimiter:
    """
    Rate limiter with different limits per endpoint
    """
    
    def __init__(self):
        self.limiters = {}
        logger.info("Endpoint Rate Limiter initialized")
    
    def add_limit(self, endpoint, max_requests, window):
        """
        Add rate limit for specific endpoint
        
        Args:
            endpoint: Endpoint path
            max_requests: Max requests allowed
            window: Time window in seconds
        """
        self.limiters[endpoint] = RateLimiter(max_requests, window)
        logger.info(f"Rate limit added for {endpoint}: {max_requests}/{window}s")
    
    def is_allowed(self, endpoint, identifier):
        """
        Check if request is allowed for endpoint
        
        Args:
            endpoint: Endpoint path
            identifier: IP or user identifier
            
        Returns:
            True if allowed, False otherwise
        """
        if endpoint not in self.limiters:
            return True
        
        return self.limiters[endpoint].is_allowed(identifier)
    
    def get_remaining(self, endpoint, identifier):
        """Get remaining requests for endpoint"""
        if endpoint not in self.limiters:
            return float('inf')
        
        return self.limiters[endpoint].get_remaining(identifier)
