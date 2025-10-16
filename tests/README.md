# BAS System Test Framework

This directory contains the test suite for the BAS (Building Automation System) project, built with modern pytest architecture optimized for MicroPython environments.

## Table of Contents

- [🚀 Running Tests](#-running-tests)
  - [Basic Commands](#basic-commands)
  - [Using the Test Runner Script](#using-the-test-runner-script)
- [📁 Directory Structure](#-directory-structure)
- [🏗️ How the Test Framework Works](#️-how-the-test-framework-works)
  - [Core Components](#core-components)
  - [Test Flow](#test-flow)
  - [Markers System](#markers-system)
- [📚 Adding New Tests](#-adding-new-tests)
- [🎯 Best Practices](#-best-practices)
  - [Test Organization](#test-organization)
  - [Fixture Usage](#fixture-usage)
- [🚀 Future Plans (Phase 3)](#-future-plans-phase-3)
  - [Integration Testing Framework](#integration-testing-framework)
  - [Performance Testing Framework](#performance-testing-framework)
  - [Security Testing Framework](#security-testing-framework)
  - [CI/CD Integration](#cicd-integration)
- [📚 Resources](#-resources)
  - [Documentation](#documentation)
  - [MicroPython Compatibility](#micropython-compatibility)

## 🚀 Running Tests

### Basic Commands
```bash
# Run all tests
python3 -m pytest tests/ -v

# Run only authentication tests
python3 -m pytest tests/unit/auth/ -v

# Run specific test file
python3 -m pytest tests/unit/auth/test_config.py -v

# Run specific test method
python3 -m pytest tests/unit/auth/test_config.py::TestAuthConfig::test_default_config -v

# Run with markers
python3 -m pytest tests/ -m auth -v
```

### Using the Test Runner Script
```bash
# Run all tests
python3 run_tests.py

# Run specific categories
python3 run_tests.py --auth
python3 run_tests.py --unit
```

## 📁 Directory Structure

```
tests/
├── README.md                    # This file
├── conftest.py                  # Global pytest configuration and fixtures
├── pytest.ini                  # Pytest configuration and markers
├── run_tests.py                # Test runner script
├── docs/                       # Detailed documentation
│   ├── framework-guide.md      # How the framework works
│   └── adding-tests-examples.md # Examples for adding new tests
├── fixtures/                   # Shared test fixtures
│   ├── __init__.py
│   └── auth_fixtures.py        # Authentication-specific fixtures
├── utils/                      # Test utilities and helpers
│   ├── __init__.py
│   └── assertions.py           # Custom assertion functions
└── unit/                       # Unit tests organized by domain
    ├── __init__.py
    └── auth/                   # Authentication unit tests
        ├── __init__.py
        ├── test_config.py      # AuthConfig tests
        ├── test_models.py      # User, Session, PendingMFA tests
        ├── test_managers.py    # UserManager, SessionManager, MFAManager tests
        ├── test_services.py    # SMSService, AuditLogger, RateLimiter tests
        ├── test_utils.py       # Utility function tests
        ├── test_middleware.py  # Middleware function tests
        └── test_exceptions.py  # Exception class tests
```

## 🏗️ How the Test Framework Works

### Core Components

**1. pytest Configuration (`pytest.ini`)**
- Automatically discovers test files (`test_*.py`)
- Defines test markers for categorization
- Sets output options (verbose, colored, short tracebacks)

**2. Global Configuration (`conftest.py`)**
- Sets up Python paths for imports
- Provides shared fixtures for all tests
- Automatically applies markers based on file paths

**3. Test Organization**
- Tests are organized by domain (auth, controller, services)
- Each domain has its own directory with related test files
- One test class per component being tested

**4. Fixtures System**
- Pre-built test objects (users, configs, database files)
- Reusable across multiple tests
- Automatic cleanup after each test

**5. Custom Assertions**
- Better error messages than standard assertions
- Consistent testing patterns across all tests
- Exception testing with context managers

### Test Flow
1. **Discovery**: pytest finds all `test_*.py` files
2. **Collection**: Imports test classes and methods
3. **Setup**: Creates fixtures and test environment
4. **Execution**: Runs each test method
5. **Teardown**: Cleans up fixtures and temporary files
6. **Reporting**: Shows results and any failures

### Markers System
- **`@pytest.mark.unit`** - Unit tests (automatically applied)
- **`@pytest.mark.auth`** - Authentication-related tests
- **`@pytest.mark.integration`** - Integration tests (future)
- **`@pytest.mark.performance`** - Performance tests (future)

## 📚 Adding New Tests

For detailed examples and step-by-step instructions on adding new tests, see:

**[📖 Adding Tests Examples](docs/adding-tests-examples.md)**

This guide includes:
- How to add a single new test to existing test files
- How to create a complete new test file for a component
- How to add a whole new set of tests for a different domain
- Best practices and common patterns
- Real examples with code snippets

## 🎯 Best Practices

### Test Organization
1. **One test class per component** - Keep related tests together
2. **Descriptive test names** - Use clear, specific names
3. **Arrange-Act-Assert pattern** - Structure tests clearly
4. **One assertion per test** - Focus on testing one behavior

### Fixture Usage
1. **Use existing fixtures** - Leverage pre-built fixtures when possible
2. **Create domain-specific fixtures** - Add new fixtures to appropriate files
3. **Keep fixtures simple** - Avoid complex setup in fixtures

## 🚀 Future Plans (Phase 3)

### Integration Testing Framework
- End-to-end authentication flows
- API endpoint integration testing
- Database integration with real operations
- External service integration

### Performance Testing Framework
- Load testing with concurrent users
- Memory usage monitoring
- Response time measurement
- Stress testing under extreme conditions

### Security Testing Framework
- Automated vulnerability scanning
- Rate limiting validation
- Session security testing
- Input validation testing

### CI/CD Integration
- GitHub Actions workflow
- Automated test execution
- Test coverage reporting
- Deployment automation

## 📚 Resources

### Documentation
- [pytest Documentation](https://docs.pytest.org/)
- [pytest Fixtures](https://docs.pytest.org/en/stable/fixture.html)
- [pytest Markers](https://docs.pytest.org/en/stable/mark.html)

### MicroPython Compatibility
- [MicroPython Documentation](https://docs.micropython.org/)
- [MicroPython Testing Best Practices](https://github.com/micropython/micropython/wiki/Contributing)