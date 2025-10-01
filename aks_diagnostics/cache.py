"""
Improved caching implementation with TTL and file persistence
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timedelta
import logging


class CacheManager:
    """Manages caching for Azure CLI responses with TTL and persistence"""
    
    def __init__(self, cache_dir: Optional[Path] = None, default_ttl: int = 3600, enabled: bool = False):
        """
        Initialize cache manager
        
        Args:
            cache_dir: Directory for cache files. Defaults to .aks_cache in current directory
            default_ttl: Default time-to-live in seconds (default: 1 hour)
            enabled: Whether caching is enabled
        """
        self.enabled = enabled
        self.default_ttl = default_ttl
        self.cache_dir = cache_dir or Path.cwd() / '.aks_cache'
        self._memory_cache = {}
        self.logger = logging.getLogger("aks_net_diagnostics.cache")
        
        if self.enabled:
            self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist"""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.warning(f"Failed to create cache directory: {e}")
            self.enabled = False
    
    def _generate_key(self, command: str) -> str:
        """Generate cache key from command"""
        return hashlib.sha256(command.encode()).hexdigest()
    
    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path for key"""
        return self.cache_dir / f"{key}.json"
    
    def get(self, command: str) -> Optional[Any]:
        """
        Get cached value for command
        
        Args:
            command: Azure CLI command string
            
        Returns:
            Cached value if found and not expired, None otherwise
        """
        if not self.enabled:
            return None
        
        key = self._generate_key(command)
        
        # Check memory cache first
        if key in self._memory_cache:
            entry = self._memory_cache[key]
            if time.time() < entry['expires_at']:
                self.logger.debug(f"Cache hit (memory): {command[:50]}...")
                return entry['data']
            else:
                # Expired, remove from memory
                del self._memory_cache[key]
        
        # Check file cache
        cache_file = self._get_cache_file(key)
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    entry = json.load(f)
                
                if time.time() < entry['expires_at']:
                    # Load into memory cache
                    self._memory_cache[key] = entry
                    self.logger.debug(f"Cache hit (file): {command[:50]}...")
                    return entry['data']
                else:
                    # Expired, delete file
                    cache_file.unlink()
                    self.logger.debug(f"Cache expired: {command[:50]}...")
            except Exception as e:
                self.logger.warning(f"Failed to read cache file: {e}")
        
        return None
    
    def set(self, command: str, data: Any, ttl: Optional[int] = None):
        """
        Cache data for command
        
        Args:
            command: Azure CLI command string
            data: Data to cache
            ttl: Time-to-live in seconds (uses default if not specified)
        """
        if not self.enabled:
            return
        
        key = self._generate_key(command)
        ttl = ttl or self.default_ttl
        expires_at = time.time() + ttl
        
        entry = {
            'command': command,
            'data': data,
            'cached_at': time.time(),
            'expires_at': expires_at
        }
        
        # Store in memory
        self._memory_cache[key] = entry
        
        # Store in file
        cache_file = self._get_cache_file(key)
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(entry, f)
            self.logger.debug(f"Cached: {command[:50]}...")
        except Exception as e:
            self.logger.warning(f"Failed to write cache file: {e}")
    
    def clear(self):
        """Clear all cache"""
        self._memory_cache.clear()
        
        if self.cache_dir.exists():
            try:
                for cache_file in self.cache_dir.glob('*.json'):
                    cache_file.unlink()
                self.logger.info("Cache cleared")
            except Exception as e:
                self.logger.warning(f"Failed to clear cache: {e}")
    
    def cleanup_expired(self):
        """Remove expired cache entries"""
        current_time = time.time()
        
        # Clean memory cache
        expired_keys = [k for k, v in self._memory_cache.items() 
                       if current_time >= v['expires_at']]
        for key in expired_keys:
            del self._memory_cache[key]
        
        # Clean file cache
        if self.cache_dir.exists():
            try:
                for cache_file in self.cache_dir.glob('*.json'):
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            entry = json.load(f)
                        if current_time >= entry['expires_at']:
                            cache_file.unlink()
                    except Exception:
                        # Remove corrupted cache files
                        cache_file.unlink()
            except Exception as e:
                self.logger.warning(f"Failed to cleanup expired cache: {e}")
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        stats = {
            'enabled': self.enabled,
            'memory_entries': len(self._memory_cache),
            'file_entries': 0,
            'cache_dir': str(self.cache_dir)
        }
        
        if self.cache_dir.exists():
            try:
                stats['file_entries'] = len(list(self.cache_dir.glob('*.json')))
            except Exception:
                pass
        
        return stats
