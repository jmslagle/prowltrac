"""
Logging utilities for Prowler OCSF to PlexTrac tool.
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional

from .config import get_config


class LoggerManager:
    """Centralized logging manager."""

    def __init__(self):
        self._loggers = {}
        self._configured = False

    def setup_logging(self, name: str = "prowltrac") -> logging.Logger:
        """Set up logging configuration."""
        if name in self._loggers:
            return self._loggers[name]

        config = get_config()
        log_config = config.logging

        # Create logger
        logger = logging.getLogger(name)
        # Set to DEBUG level to capture authentication details in log file
        logger.setLevel(logging.DEBUG)

        # Clear existing handlers to avoid duplicates
        logger.handlers.clear()

        # Create formatter
        formatter = logging.Formatter(log_config.format)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File handler with rotation (always enabled)
        log_path = Path(log_config.file)
        log_path.parent.mkdir(exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=log_config.max_size_mb * 1024 * 1024,
            backupCount=log_config.backup_count,
        )
        # File handler uses DEBUG level to capture all details
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Prevent propagation to root logger
        logger.propagate = False

        self._loggers[name] = logger
        return logger

    def get_logger(self, name: str = "prowltrac") -> logging.Logger:
        """Get or create a logger."""
        if name not in self._loggers:
            return self.setup_logging(name)
        return self._loggers[name]


# Global logger manager
logger_manager = LoggerManager()


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance."""
    logger_name = name or "prowltrac"
    return logger_manager.get_logger(logger_name)


def log_api_request(
    logger: logging.Logger, method: str, url: str, status_code: Optional[int] = None
):
    """Log API request details."""
    if status_code:
        logger.info(f"API {method} {url} -> {status_code}")
    else:
        logger.info(f"API {method} {url}")


def log_import_progress(logger: logging.Logger, current: int, total: int, message: str = ""):
    """Log import progress."""
    progress = (current / total) * 100 if total > 0 else 0
    logger.info(f"Import progress: {current}/{total} ({progress:.1f}%) {message}")


def log_filter_results(
    logger: logging.Logger, original_count: int, filtered_count: int, filters: dict
):
    """Log filtering results."""
    logger.info(f"Filtered {original_count} findings to {filtered_count} using filters: {filters}")


def log_authentication(logger: logging.Logger, success: bool, username: str = ""):
    """Log authentication attempts."""
    if success:
        logger.info(f"Successfully authenticated user: {username}")
    else:
        logger.warning(f"Authentication failed for user: {username}")


def log_file_operation(
    logger: logging.Logger, operation: str, file_path: str, success: bool = True
):
    """Log file operations."""
    status = "success" if success else "failed"
    logger.info(f"File {operation} {status}: {file_path}")
