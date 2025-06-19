# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-06-18

### Added
- **Menu-driven interface** (`menu_import.py`) with interactive file selection, filtering, and import progress
- **CLI automation interface** (`simple_import.py`) with comprehensive command-line options
- **Full OCSF parsing** with proper field mapping and error handling
- **Advanced filtering system** with status (FAIL/PASS) and severity (Critical/High/Medium/Low) filters
- **Smart asset management** - automatically creates AWS account assets from OCSF data
- **Enhanced PlexTrac integration** with proper API endpoints and error handling
- **Token caching system** with encryption for authentication persistence
- **Duplicate finding detection** - gracefully handles "title already exists" errors
- **Clean data extraction** - properly parses recommendations and references from OCSF format
- **Comprehensive configuration** via environment variables, config files, and CLI options
- **Debug logging** with `--debug` flag for troubleshooting API issues
- **Progress tracking** with real-time import status and detailed reporting

### Security
- **Apache 2.0 License** applied to all source code
- **Encrypted token storage** using Fernet symmetric encryption
- **Secure credential handling** with environment variable support
- **Input validation** for OCSF files and API responses

### Documentation
- **Comprehensive README** with installation, usage, and troubleshooting guides
- **CLI help text** with examples and filter explanations
- **GitHub workflows** for CI/CD, security scanning, and automated testing
- **Contributing guide** for developers
- **Issue templates** for bug reports and feature requests

### Technical Features
- **Multi-interface design**: Both interactive menu and CLI automation
- **Robust error handling**: Graceful failure modes with detailed logging
- **Configurable filtering**: 6 different filter types including OR logic
- **Asset pre-creation**: Ensures PlexTrac assets exist before importing findings
- **Batch processing**: Efficient handling of large finding sets
- **API endpoint discovery**: Handles PlexTrac v1/v2 API variations
- **Status code filtering**: Uses OCSF `status_code` field for accurate FAIL/PASS filtering

### Dependencies
- `requests` - HTTP client for PlexTrac API
- `pydantic` - Data validation and configuration
- `PyYAML` - Configuration file support
- `python-dotenv` - Environment variable loading
- `cryptography` - Token encryption
- `simple-term-menu` - Interactive menu system

### Development
- **Test suite** with pytest, including integration and filter tests
- **GitHub Actions** CI/CD with multi-Python version testing
- **Code quality tools** - black, isort, flake8, mypy
- **Security scanning** - bandit, safety, CodeQL
- **Mock testing** for PlexTrac API integration

---

## Development Notes

This initial release was rapidly developed in a few hours with assistance from [Claude Code](https://claude.ai/code). While functional and tested, expect rough edges and improvements in future releases.

**Found a bug?** Please [file an issue](https://github.com/jmslagle/prowltrac/issues) - your feedback helps improve the tool!