# Contributing to Prowltrac

Thank you for your interest in contributing to Prowltrac! This guide will help you get started.

## Quick Start

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/jmslagle/prowltrac.git
   cd prowltrac
   ```

2. **Set up development environment**
   ```bash
   # Install dependencies
   pip install -e .[dev,test]
   
   # Run tests to verify setup
   pytest
   ```

3. **Make your changes**
   - Create a feature branch: `git checkout -b feature/your-feature-name`
   - Make your changes
   - Add tests for new functionality
   - Run tests: `pytest`

4. **Submit a pull request**
   - Push your branch: `git push origin feature/your-feature-name`
   - Create a pull request on GitHub

## Development Guidelines

### Code Style & Quality Checks

We use automated formatting, linting, and security checks. **Run these locally before submitting PRs:**

#### **Formatting (Required)**
```bash
# Auto-format code with black
python -m black src/ tests/

# Sort imports
python -m isort src/ tests/

# Check formatting without making changes
python -m black --check src/ tests/
```

#### **Linting**
```bash
# Check code style
python -m flake8 src/ tests/

# Type checking
python -m mypy src/
```

#### **Security Checks**
```bash
# Install security tools
pip install bandit safety

# Check for security issues in code
python -m bandit -r src/ -f json -o bandit-report.json

# Check for known vulnerabilities in dependencies
python -m safety check --json --output safety-report.json
```

#### **Pre-commit Setup**
Install pre-commit hooks to run these checks automatically:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

#### **Quick Check Script**
Run all checks at once:

```bash
# Create a simple check script
cat > check_code.sh << 'EOF'
#!/bin/bash
set -e

echo "🔍 Running code quality checks..."

echo "📝 Formatting with black..."
python -m black src/ tests/

echo "📋 Sorting imports..."
python -m isort src/ tests/

echo "🔍 Linting with flake8..."
python -m flake8 src/ tests/

echo "🔒 Security scan with bandit..."
python -m bandit -r src/ -f json -o bandit-report.json

echo "🛡️ Dependency check with safety..."
python -m safety check --json --output safety-report.json

echo "✅ All checks passed!"
EOF

chmod +x check_code.sh
./check_code.sh
```

### Testing

- Add tests for all new functionality
- Ensure all tests pass: `pytest`
- Check test coverage: `pytest --cov=src`

### Commit Messages

Use clear, descriptive commit messages:
- `feat: add support for new OCSF field`
- `fix: handle empty findings list gracefully`
- `docs: update CLI usage examples`

## Areas for Contribution

### 🐛 **Bug Fixes**
- PlexTrac API edge cases
- OCSF parsing issues
- Authentication problems
- CLI/menu bugs

### ✨ **Features**
- New filter types
- Additional OCSF field support
- PlexTrac API enhancements
- Export formats
- Configuration improvements

### 📚 **Documentation**
- Usage examples
- API documentation
- Troubleshooting guides
- Video tutorials

### 🧪 **Testing**
- Integration tests
- Edge case coverage
- Performance tests
- Mock PlexTrac scenarios

## Development Tips

### Testing with Real Data

1. **Sample OCSF files**: Add realistic test cases to `tests/fixtures/`
2. **Mock PlexTrac**: Use `unittest.mock` for API tests
3. **Integration tests**: Test the full workflow end-to-end

### Debugging

```bash
# Enable debug logging
python menu_import.py --debug
python simple_import.py --debug your-file.json

# Check logs
tail -f prowltrac.log
```

### Local PlexTrac Testing

If you have access to a PlexTrac instance:

```bash
# Set up environment
export PLEXTRAC_URL="https://your-test-instance.plextrac.com"
export PLEXTRAC_USERNAME="test-user"
export PLEXTRAC_PASSWORD="test-password"

# Test with sample data
python simple_import.py tests/fixtures/sample_ocsf.json --show-stats
```

## Code Organization

```
src/
├── api/endpoints.py      # PlexTrac API wrappers
├── auth/                 # Authentication system
├── filters.py           # Finding filters
├── ocsf_parser.py       # OCSF parsing logic
├── plextrac_client.py   # High-level client
└── utils/               # Utilities and config
```

## Common Tasks

### Adding a New Filter Type

1. Create filter class in `src/filters.py`
2. Add to `FilterEngine.create_from_preset()`
3. Add CLI option to `simple_import.py`
4. Add menu option to `menu_import.py`
5. Add tests in `tests/test_filters.py`

### Adding OCSF Field Support

1. Update `OCSFFinding` dataclass in `src/ocsf_parser.py`
2. Update `_parse_finding()` method
3. Update conversion logic in both import scripts
4. Add test cases

### Adding PlexTrac API Features

1. Add methods to `src/api/endpoints.py`
2. Update `PlexTracClient` in `src/plextrac_client.py`
3. Add error handling
4. Add tests with mocks

## Release Process

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create release tag
4. GitHub Actions will run tests automatically

## Getting Help

- **Issues**: Check existing [GitHub issues](https://github.com/jmslagle/prowltrac/issues)
- **Discussions**: Start a [GitHub discussion](https://github.com/jmslagle/prowltrac/discussions)
- **Questions**: Open an issue with the `question` label

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers get started
- Share knowledge and learn from others

---

**Remember**: This tool was built rapidly with AI assistance, so there are definitely opportunities for improvement. Your contributions help make it better for everyone! 🚀