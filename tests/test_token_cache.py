"""
Tests for token cache module.
"""

import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

from src.auth.token_cache import TokenCache, TokenCacheError


class TestTokenCache:
    """Test cases for TokenCache."""

    def setup_method(self):
        """Set up test fixtures."""
        # Use temporary directory for testing
        self.temp_dir = Path(tempfile.mkdtemp())
        self.cache = TokenCache(cache_dir=self.temp_dir)

        # Sample token data
        self.sample_url = "https://test.plextrac.com"
        self.sample_username = "testuser"
        self.sample_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test"
        self.sample_expires = datetime.now() + timedelta(minutes=15)
        self.sample_user_info = {"id": "123", "name": "Test User"}

    def teardown_method(self):
        """Clean up test fixtures."""
        # Clean up temporary directory
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_and_load_token(self):
        """Test saving and loading a token."""
        # Save token
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=self.sample_expires,
            user_info=self.sample_user_info,
        )

        # Load token
        loaded_token = self.cache.load_token(self.sample_url, self.sample_username)

        assert loaded_token is not None
        assert loaded_token["token"] == self.sample_token
        assert loaded_token["username"] == self.sample_username
        assert loaded_token["plextrac_url"] == self.sample_url
        assert loaded_token["user_info"] == self.sample_user_info

    def test_load_nonexistent_token(self):
        """Test loading a token that doesn't exist."""
        loaded_token = self.cache.load_token("https://nonexistent.com", "nouser")
        assert loaded_token is None

    def test_remove_token(self):
        """Test removing a token."""
        # Save token first
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=self.sample_expires,
        )

        # Verify it exists
        loaded_token = self.cache.load_token(self.sample_url, self.sample_username)
        assert loaded_token is not None

        # Remove token
        result = self.cache.remove_token(self.sample_url, self.sample_username)
        assert result is True

        # Verify it's gone
        loaded_token = self.cache.load_token(self.sample_url, self.sample_username)
        assert loaded_token is None

    def test_expired_token_removal(self):
        """Test that expired tokens are automatically removed."""
        # Save expired token
        expired_time = datetime.now() - timedelta(minutes=1)
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=expired_time,
        )

        # Try to load - should return None and remove the token
        loaded_token = self.cache.load_token(self.sample_url, self.sample_username)
        assert loaded_token is None

    def test_list_cached_tokens(self):
        """Test listing cached tokens."""
        # Save a couple of tokens
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=self.sample_expires,
        )

        self.cache.save_token(
            plextrac_url="https://test2.plextrac.com",
            username="user2",
            token="token2",
            expires_at=self.sample_expires,
        )

        # List tokens
        tokens = self.cache.list_cached_tokens()

        assert len(tokens) == 2
        assert any(t["full_username"] == self.sample_username for t in tokens)
        assert any(t["full_username"] == "user2" for t in tokens)

    def test_cleanup_expired_tokens(self):
        """Test cleanup of expired tokens."""
        # Save one valid and one expired token
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=self.sample_expires,  # Valid
        )

        expired_time = datetime.now() - timedelta(minutes=1)
        self.cache.save_token(
            plextrac_url="https://test2.plextrac.com",
            username="expired_user",
            token="expired_token",
            expires_at=expired_time,  # Expired
        )

        # Cleanup
        removed_count = self.cache.cleanup_expired_tokens()

        assert removed_count == 1

        # Verify only valid token remains
        tokens = self.cache.list_cached_tokens()
        assert len(tokens) == 1
        assert tokens[0]["full_username"] == self.sample_username

    def test_clear_cache(self):
        """Test clearing all cached tokens."""
        # Save some tokens
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=self.sample_expires,
        )

        # Clear cache
        self.cache.clear_cache()

        # Verify cache is empty
        tokens = self.cache.list_cached_tokens()
        assert len(tokens) == 0

    def test_get_cache_info(self):
        """Test getting cache information."""
        # Save some tokens
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=self.sample_expires,
        )

        # Get cache info
        info = self.cache.get_cache_info()

        assert "cache_dir" in info
        assert "total_tokens" in info
        assert "valid_tokens" in info
        assert "expired_tokens" in info
        assert info["total_tokens"] >= 1

    def test_encryption_key_generation(self):
        """Test that encryption keys are properly generated."""
        # The key should be generated automatically
        assert self.cache._encryption_key is not None
        assert self.cache.key_file.exists()

        # Key file should have secure permissions
        import stat

        file_mode = self.cache.key_file.stat().st_mode
        assert stat.filemode(file_mode) == "-rw-------"

    def test_cache_file_permissions(self):
        """Test that cache files have secure permissions."""
        # Save a token to create cache file
        self.cache.save_token(
            plextrac_url=self.sample_url,
            username=self.sample_username,
            token=self.sample_token,
            expires_at=self.sample_expires,
        )

        # Check cache file permissions
        import stat

        file_mode = self.cache.cache_file.stat().st_mode
        assert stat.filemode(file_mode) == "-rw-------"

    @patch("src.auth.token_cache.Fernet")
    def test_encryption_error_handling(self, mock_fernet):
        """Test handling of encryption errors."""
        # Mock encryption failure
        mock_fernet.side_effect = Exception("Encryption failed")

        # Should raise TokenCacheError
        with pytest.raises(TokenCacheError):
            self.cache._generate_new_key()

    def test_invalid_cache_data_handling(self):
        """Test handling of corrupted cache data."""
        # Create invalid cache file
        with open(self.cache.cache_file, "w") as f:
            f.write("invalid json {")

        # Should handle gracefully
        tokens = self.cache.list_cached_tokens()
        assert tokens == []

    def test_cache_key_consistency(self):
        """Test that cache keys are consistent."""
        # Same URL/username should generate same cache key
        key1 = self.cache._get_cache_key(self.sample_url, self.sample_username)
        key2 = self.cache._get_cache_key(self.sample_url, self.sample_username)

        assert key1 == key2

        # Different URL/username should generate different keys
        key3 = self.cache._get_cache_key("https://different.com", self.sample_username)
        assert key1 != key3

        key4 = self.cache._get_cache_key(self.sample_url, "different_user")
        assert key1 != key4
