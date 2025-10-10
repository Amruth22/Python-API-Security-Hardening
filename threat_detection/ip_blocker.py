"""
IP Blocker
Manages IP blacklist and whitelist
"""

import logging
import time
from collections import defaultdict

logger = logging.getLogger(__name__)


class IPBlocker:
    """
    IP blocking system
    Manages blacklist, whitelist, and temporary blocks
    """
    
    def __init__(self):
        self.blacklist = set()
        self.whitelist = set()
        self.temporary_blocks = {}  # {ip: unblock_time}
        self.block_history = []
        
        logger.info("IP Blocker initialized")
    
    def block_ip(self, ip, reason="", duration=None):
        """
        Block an IP address
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for permanent)
        """
        if duration:
            # Temporary block
            unblock_time = time.time() + duration
            self.temporary_blocks[ip] = unblock_time
            logger.warning(f"IP temporarily blocked: {ip} for {duration}s - {reason}")
        else:
            # Permanent block
            self.blacklist.add(ip)
            logger.warning(f"IP permanently blocked: {ip} - {reason}")
        
        # Record in history
        self.block_history.append({
            'ip': ip,
            'reason': reason,
            'duration': duration,
            'timestamp': time.time()
        })
    
    def unblock_ip(self, ip):
        """
        Unblock an IP address
        
        Args:
            ip: IP address to unblock
        """
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            logger.info(f"IP unblocked: {ip}")
        
        if ip in self.temporary_blocks:
            del self.temporary_blocks[ip]
            logger.info(f"IP temporary block removed: {ip}")
    
    def is_blocked(self, ip):
        """
        Check if IP is blocked
        
        Args:
            ip: IP address to check
            
        Returns:
            True if blocked, False otherwise
        """
        # Check whitelist first
        if ip in self.whitelist:
            return False
        
        # Check permanent blacklist
        if ip in self.blacklist:
            return True
        
        # Check temporary blocks
        if ip in self.temporary_blocks:
            unblock_time = self.temporary_blocks[ip]
            
            if time.time() < unblock_time:
                return True
            else:
                # Block expired, remove it
                del self.temporary_blocks[ip]
                logger.info(f"Temporary block expired for {ip}")
                return False
        
        return False
    
    def whitelist_ip(self, ip):
        """
        Add IP to whitelist
        
        Args:
            ip: IP address to whitelist
        """
        self.whitelist.add(ip)
        
        # Remove from blacklist if present
        if ip in self.blacklist:
            self.blacklist.remove(ip)
        
        logger.info(f"IP whitelisted: {ip}")
    
    def get_blocked_ips(self):
        """Get all blocked IPs"""
        current_time = time.time()
        
        # Permanent blocks
        permanent = list(self.blacklist)
        
        # Active temporary blocks
        temporary = [
            ip for ip, unblock_time in self.temporary_blocks.items()
            if current_time < unblock_time
        ]
        
        return {
            'permanent': permanent,
            'temporary': temporary,
            'total': len(permanent) + len(temporary)
        }
    
    def get_stats(self):
        """Get IP blocker statistics"""
        blocked = self.get_blocked_ips()
        
        return {
            'blacklist_size': len(self.blacklist),
            'whitelist_size': len(self.whitelist),
            'temporary_blocks': len(blocked['temporary']),
            'total_blocked': blocked['total'],
            'block_history_size': len(self.block_history)
        }
