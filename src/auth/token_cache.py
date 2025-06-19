"""
Token caching system for PlexTrac authentication.
Securely stores and manages JWT tokens locally.
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..utils.logger import get_logger
from ..utils.config import get_config


class TokenCacheError(Exception):
    """Custom exception for token cache errors."""
    pass


class TokenCache:
    """Secure token cache manager."""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # Cache directory
        self.cache_dir = cache_dir or Path.home() / '.prowltrac'
        self.cache_dir.mkdir(exist_ok=True, mode=0o700)  # Secure permissions
        
        # Cache file
        self.cache_file = self.cache_dir / 'token_cache.json'
        self.key_file = self.cache_dir / '.cache_key'
        
        # Encryption key
        self._encryption_key: Optional[bytes] = None
        self._ensure_encryption_key()
    
    def _ensure_encryption_key(self) -> None:
        """Ensure encryption key exists and is loaded."""
        if self.key_file.exists():
            # Load existing key
            try:
                with open(self.key_file, 'rb') as f:
                    self._encryption_key = f.read()
            except Exception as e:
                self.logger.warning(f"Could not load encryption key: {e}")
                self._generate_new_key()
        else:
            # Generate new key
            self._generate_new_key()
    
    def _generate_new_key(self) -> None:
        """Generate a new encryption key."""
        try:
            # Generate a key from system entropy
            key = Fernet.generate_key()
            
            # Save key with secure permissions
            with open(self.key_file, 'wb') as f:
                f.write(key)
            
            # Set secure file permissions
            os.chmod(self.key_file, 0o600)
            
            self._encryption_key = key
            self.logger.debug("Generated new encryption key")
            
        except Exception as e:
            raise TokenCacheError(f"Failed to generate encryption key: {e}")
    
    def _get_cipher(self) -> Fernet:
        """Get encryption cipher."""
        if not self._encryption_key:
            raise TokenCacheError("Encryption key not available")
        return Fernet(self._encryption_key)
    
    def _get_cache_key(self, plextrac_url: str, username: str) -> str:
        """Generate cache key for user/URL combination."""
        # Create a hash of URL + username for the cache key
        key_data = f"{plextrac_url.lower().rstrip('/')}/{username.lower()}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    def save_token(self, plextrac_url: str, username: str, token: str, 
                   expires_at: datetime, user_info: Optional[Dict[str, Any]] = None) -> None:
        """Save token to cache."""
        try:
            cache_key = self._get_cache_key(plextrac_url, username)
            
            # Load existing cache
            cache_data = self._load_cache()
            
            # Prepare token data
            token_data = {
                'token': token,
                'expires_at': expires_at.isoformat(),
                'plextrac_url': plextrac_url,
                'username': username,
                'saved_at': datetime.now().isoformat(),
                'user_info': user_info or {}
            }
            
            # Encrypt token data
            cipher = self._get_cipher()
            encrypted_data = cipher.encrypt(json.dumps(token_data).encode())
            
            # Store in cache
            cache_data[cache_key] = {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'username_hint': username[:3] + '*' * (len(username) - 3),  # Partial username for identification
                'url_hint': plextrac_url.split('//')[1].split('.')[0] if '//' in plextrac_url else plextrac_url[:10],
                'saved_at': datetime.now().isoformat()
            }
            
            # Save cache
            self._save_cache(cache_data)
            
            self.logger.info(f"Saved token for {username} at {plextrac_url}")
            
        except Exception as e:
            self.logger.error(f"Failed to save token: {e}")
            raise TokenCacheError(f"Failed to save token: {e}")
    
    def load_token(self, plextrac_url: str, username: str) -> Optional[Dict[str, Any]]:
        """Load token from cache."""
        try:
            cache_key = self._get_cache_key(plextrac_url, username)
            
            # Load cache
            cache_data = self._load_cache()
            
            if cache_key not in cache_data:
                return None
            
            # Get encrypted data
            cached_item = cache_data[cache_key]
            encrypted_data = base64.b64decode(cached_item['encrypted_data'])
            
            # Decrypt
            cipher = self._get_cipher()
            decrypted_data = cipher.decrypt(encrypted_data)
            token_data = json.loads(decrypted_data.decode())
            
            # Check expiration
            expires_at = datetime.fromisoformat(token_data['expires_at'])
            if expires_at <= datetime.now():
                self.logger.debug(f"Token expired for {username}")
                self.remove_token(plextrac_url, username)
                return None
            
            self.logger.info(f"Loaded valid token for {username}")
            return token_data
            
        except Exception as e:
            self.logger.warning(f"Failed to load token: {e}")
            return None
    
    def remove_token(self, plextrac_url: str, username: str) -> bool:
        """Remove token from cache."""
        try:
            cache_key = self._get_cache_key(plextrac_url, username)
            
            # Load cache
            cache_data = self._load_cache()
            
            if cache_key in cache_data:
                del cache_data[cache_key]
                self._save_cache(cache_data)
                self.logger.info(f"Removed token for {username}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to remove token: {e}")
            return False
    
    def clear_cache(self) -> None:
        """Clear all cached tokens."""
        try:
            if self.cache_file.exists():
                self.cache_file.unlink()
            self.logger.info("Cleared token cache")
        except Exception as e:
            self.logger.error(f"Failed to clear cache: {e}")
            raise TokenCacheError(f"Failed to clear cache: {e}")
    
    def list_cached_tokens(self) -> List[Dict[str, str]]:
        """List all cached tokens (without sensitive data)."""
        try:
            cache_data = self._load_cache()
            
            tokens = []
            for cache_key, cached_item in cache_data.items():
                try:
                    # Try to decrypt to check validity
                    encrypted_data = base64.b64decode(cached_item['encrypted_data'])
                    cipher = self._get_cipher()
                    decrypted_data = cipher.decrypt(encrypted_data)
                    token_data = json.loads(decrypted_data.decode())
                    
                    expires_at = datetime.fromisoformat(token_data['expires_at'])
                    is_expired = expires_at <= datetime.now()
                    
                    tokens.append({
                        'username_hint': cached_item['username_hint'],
                        'url_hint': cached_item['url_hint'],
                        'saved_at': cached_item['saved_at'],
                        'expires_at': token_data['expires_at'],
                        'is_expired': is_expired,
                        'full_url': token_data['plextrac_url'],
                        'full_username': token_data['username']
                    })
                    
                except Exception:
                    # Skip invalid entries
                    continue
            
            return tokens
            
        except Exception as e:
            self.logger.error(f"Failed to list tokens: {e}")
            return []
    
    def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from cache."""
        try:
            cache_data = self._load_cache()
            removed_count = 0
            
            keys_to_remove = []
            for cache_key, cached_item in cache_data.items():
                try:
                    encrypted_data = base64.b64decode(cached_item['encrypted_data'])
                    cipher = self._get_cipher()
                    decrypted_data = cipher.decrypt(encrypted_data)
                    token_data = json.loads(decrypted_data.decode())
                    
                    expires_at = datetime.fromisoformat(token_data['expires_at'])
                    if expires_at <= datetime.now():
                        keys_to_remove.append(cache_key)
                        
                except Exception:
                    # Remove invalid entries too
                    keys_to_remove.append(cache_key)
            
            # Remove expired/invalid tokens
            for key in keys_to_remove:
                del cache_data[key]
                removed_count += 1
            
            if removed_count > 0:
                self._save_cache(cache_data)
                self.logger.info(f"Cleaned up {removed_count} expired tokens")
            
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup tokens: {e}")
            return 0
    
    def _load_cache(self) -> Dict[str, Any]:
        """Load cache data from file."""
        try:
            if not self.cache_file.exists():
                return {}
            
            with open(self.cache_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            self.logger.warning(f"Failed to load cache, starting fresh: {e}")
            return {}
    
    def _save_cache(self, cache_data: Dict[str, Any]) -> None:
        """Save cache data to file."""
        try:
            # Create temporary file first
            temp_file = self.cache_file.with_suffix('.tmp')
            
            with open(temp_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Set secure permissions
            os.chmod(temp_file, 0o600)
            
            # Atomic rename
            temp_file.replace(self.cache_file)
            
        except Exception as e:
            raise TokenCacheError(f"Failed to save cache: {e}")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information and statistics."""
        try:
            cache_data = self._load_cache()
            
            total_tokens = len(cache_data)
            valid_tokens = 0
            expired_tokens = 0
            
            for cached_item in cache_data.values():
                try:
                    encrypted_data = base64.b64decode(cached_item['encrypted_data'])
                    cipher = self._get_cipher()
                    decrypted_data = cipher.decrypt(encrypted_data)
                    token_data = json.loads(decrypted_data.decode())
                    
                    expires_at = datetime.fromisoformat(token_data['expires_at'])
                    if expires_at <= datetime.now():
                        expired_tokens += 1
                    else:
                        valid_tokens += 1
                        
                except Exception:
                    expired_tokens += 1
            
            return {
                'cache_dir': str(self.cache_dir),
                'cache_file': str(self.cache_file),
                'total_tokens': total_tokens,
                'valid_tokens': valid_tokens,
                'expired_tokens': expired_tokens,
                'cache_file_exists': self.cache_file.exists(),
                'cache_file_size': self.cache_file.stat().st_size if self.cache_file.exists() else 0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get cache info: {e}")
            return {'error': str(e)}


# Global token cache instance
token_cache = TokenCache()