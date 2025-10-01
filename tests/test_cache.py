"""
Unit tests for cache module
"""

import unittest
import time
import tempfile
import shutil
from pathlib import Path
from aks_diagnostics.cache import CacheManager


class TestCacheManager(unittest.TestCase):
    """Test cache manager functionality"""
    
    def setUp(self):
        """Set up test cache directory"""
        self.test_cache_dir = Path(tempfile.mkdtemp())
        self.cache = CacheManager(
            cache_dir=self.test_cache_dir,
            default_ttl=2,  # 2 seconds for testing
            enabled=True
        )
    
    def tearDown(self):
        """Clean up test cache directory"""
        if self.test_cache_dir.exists():
            shutil.rmtree(self.test_cache_dir)
    
    def test_cache_disabled(self):
        """Test cache when disabled"""
        cache = CacheManager(enabled=False)
        
        cache.set('test command', {'data': 'value'})
        result = cache.get('test command')
        
        self.assertIsNone(result)
    
    def test_cache_set_and_get(self):
        """Test basic cache set and get"""
        command = 'az aks show -n test -g rg'
        data = {'name': 'test', 'location': 'eastus'}
        
        self.cache.set(command, data)
        result = self.cache.get(command)
        
        self.assertEqual(result, data)
    
    def test_cache_miss(self):
        """Test cache miss"""
        result = self.cache.get('nonexistent command')
        self.assertIsNone(result)
    
    def test_cache_expiration(self):
        """Test cache expiration with TTL"""
        command = 'az aks list'
        data = [{'name': 'cluster1'}, {'name': 'cluster2'}]
        
        self.cache.set(command, data, ttl=1)  # 1 second TTL
        
        # Should be cached immediately
        result = self.cache.get(command)
        self.assertEqual(result, data)
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Should be expired
        result = self.cache.get(command)
        self.assertIsNone(result)
    
    def test_cache_persistence(self):
        """Test cache persistence to file"""
        command = 'az network vnet list'
        data = {'vnets': ['vnet1', 'vnet2']}
        
        self.cache.set(command, data)
        
        # Create new cache manager with same directory
        new_cache = CacheManager(cache_dir=self.test_cache_dir, enabled=True)
        result = new_cache.get(command)
        
        self.assertEqual(result, data)
    
    def test_cache_clear(self):
        """Test cache clearing"""
        commands = [
            ('cmd1', {'data': 1}),
            ('cmd2', {'data': 2}),
            ('cmd3', {'data': 3})
        ]
        
        for cmd, data in commands:
            self.cache.set(cmd, data)
        
        # Verify cached
        for cmd, data in commands:
            self.assertEqual(self.cache.get(cmd), data)
        
        # Clear cache
        self.cache.clear()
        
        # Verify cleared
        for cmd, _ in commands:
            self.assertIsNone(self.cache.get(cmd))
    
    def test_cleanup_expired(self):
        """Test cleanup of expired entries"""
        # Add entries with different TTLs
        self.cache.set('short_ttl', {'data': 'short'}, ttl=1)
        self.cache.set('long_ttl', {'data': 'long'}, ttl=10)
        
        # Wait for short TTL to expire
        time.sleep(1.5)
        
        # Cleanup expired
        self.cache.cleanup_expired()
        
        # Short TTL should be gone
        self.assertIsNone(self.cache.get('short_ttl'))
        
        # Long TTL should still exist
        self.assertEqual(self.cache.get('long_ttl'), {'data': 'long'})
    
    def test_get_stats(self):
        """Test cache statistics"""
        self.cache.set('cmd1', {'data': 1})
        self.cache.set('cmd2', {'data': 2})
        
        stats = self.cache.get_stats()
        
        self.assertTrue(stats['enabled'])
        self.assertEqual(stats['memory_entries'], 2)
        self.assertGreaterEqual(stats['file_entries'], 2)
        self.assertEqual(stats['cache_dir'], str(self.test_cache_dir))


if __name__ == '__main__':
    unittest.main()
