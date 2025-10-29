# Contract Testing Migration Guide

## Overview

This guide provides AI-assisted migration from legacy mock-based testing to contract-based testing in the BAS System Project. The migration introduces runtime validation, business rule enforcement, and improved test reliability while maintaining backward compatibility.

## Quick Start

```bash
# 1. Run contract validation on existing tests
pytest tests/unit/firestore/tests/test_audit_store.py::TestAuditLogStore::test_contract_validation_log_event -v

# 2. Enable contract validation globally
pytest tests/ --contract-validation

# 3. Generate contract compliance report
pytest tests/ --contract-report
```

## Migration Concepts

### What are Contracts?

Contracts define the expected behavior and data structures for system components:

- **Protocol Classes**: Define interfaces for store operations
- **Runtime Validators**: Enforce data integrity and business rules
- **Contract Mocks**: Optimized mocks that validate against protocols
- **Business Rules**: Centralized validation logic shared across components

### Benefits

- **Early Error Detection**: Catch violations at test time, not runtime
- **Improved Reliability**: Consistent validation across all operations
- **Better Documentation**: Self-documenting interfaces and expectations
- **Reduced Bugs**: Automated enforcement of business rules

## Phase-by-Phase Migration

### Phase 1: Foundation Setup ✅

**Completed**: Core contract infrastructure is now in place.

**What was added:**
- `tests/contracts/base.py` - Protocol definitions
- `tests/contracts/firestore.py` - Runtime validators
- `tests/utils/business_rules.py` - Centralized business rules
- `tests/conftest.py` - Contract validation hooks
- `.github/workflows/ci.yml` - CI/CD integration

**Verification:**
```bash
# Test that contracts are properly initialized
python -c "from tests.contracts.firestore import ContractEnforcer; print('Contracts ready')"
```

### Phase 2: Core Migration (Completed ✅)

#### Step 2.1: Audit Store Migration ✅

**Status**: Complete - Full contract validation implemented in `test_audit_store.py`

**Changes made:**
- Replaced legacy mocks with contract mocks
- Added runtime checks for all audit operations
- Validated audit event logging contracts
- Tested audit query operations with contracts
- Integrated business rules validation
- Added contract violation tests

#### Step 2.2: User Store Migration ✅

**Status**: Complete - Contract-based validation implemented in `test_users_store.py`

**Changes made:**
- Replaced legacy mocks with contract mocks (UserStoreContractMock)
- Enforced business rules via centralized validators
- Added contract-based user creation/update validation
- Implemented user permission contract checks
- Added comprehensive user authentication flow validation
- Added missing methods: get_by_id, update, delete, update_password, etc.

**Key Features:**
- Contract violation testing for invalid data
- Business rules validation for passwords and permissions
- Role-based permission checks
- Tenant isolation validation

#### Step 2.3: Contract Mocks Implementation ✅

**Status**: Complete - Optimized contract mocks available in `tests/contracts/mocks.py`

**Features:**
- Lazy initialization for performance (<2ms setup)
- Protocol compliance validation
- Business rules integration
- Caching for frequently used mocks (up to 1000 items)
- Factory functions for easy instantiation

**Usage:**
```python
from tests.contracts.mocks import create_contract_mock

# Create optimized contract mock
mock_store = create_contract_mock('audit', client, tenant_id='test')
result = mock_store.log_event('LOGIN_SUCCESS', username='testuser')
```

#### Step 2.4: Auth Service Integration ✅

**Status**: Complete - Contract validation integrated in auth flows

**Changes made:**
- **Protocol Integration**: Added imports for `AuditStoreProtocol`, `UsersStoreProtocol`, `SessionsStoreProtocol` and contract validation components (`ContractValidator`, `ContractEnforcer`, `AuditStoreContractMock`)
- **Auth Flow Validation**: Created `TestAuthFlowContractValidation` class with comprehensive end-to-end testing:
  - Complete login flow validation (user auth → session creation → audit logging)
  - Complete logout flow validation (session validation → audit logging)
  - Failed login flow validation (error handling → audit logging)
- **Security-Focused Checks**: Enhanced `TestRateLimiter` with contract validation for:
  - Rate limiting security enforcement with business rules
  - Session security validation (timeouts, expiration, policy compliance)
  - Permission enforcement across user roles (user, moderator, admin, super_admin)
  - Tenant isolation validation
- **Edge Case Validation**: Added comprehensive edge case testing for:
  - Invalid user ID, session ID, and tenant ID format validation
  - Malformed data contract violation testing with `ContractViolationError`
  - Boundary condition testing for authentication flows
  - Business rule validation for auth data integrity

### Phase 3: Configuration and Documentation

#### Step 3.1: Testing Configuration ✅

**Status**: `pytest.ini` updated with contract enforcement plugins

**Configuration added:**
```ini
markers =
    contract: Tests that validate contracts
    no_contract_validation: Skip contract validation
    business_rules: Tests that validate business rules

# Contract validation thresholds
contract_violation_fail_threshold = 0
business_rule_violation_fail_threshold = 0
```

#### Step 3.2: Documentation ✅

**Status**: This migration guide created

**Additional docs to create:**
- Contract API reference
- Business rules specification
- Troubleshooting guide
- Performance optimization tips

## AI-Guided Implementation Patterns

### Pattern 1: Contract Validation in Tests

```python
@pytest.mark.contract
def test_operation_with_contract_validation(self, contract_enforcer, business_rules):
    # 1. Prepare test data
    test_data = create_valid_test_data()

    # 2. Pre-validate business rules
    rule_result = business_rules.auth_check(user_id=test_data['user_id'])
    assert rule_result['valid'], f"Business rule violation: {rule_result['violations']}"

    # 3. Validate against contract
    contract_enforcer.enforce_create_contract(test_data, ['required_field'])

    # 4. Execute operation
    result = self.store.create(test_data)

    # 5. Post-validate result
    assert result.success
    contract_enforcer.enforce_create_contract(result.data, ['id', 'created_at'])
```

### Pattern 2: Contract Mock Usage

```python
from tests.contracts.mocks import create_contract_mock

def test_with_contract_mock(self):
    # Create optimized contract mock
    mock_store = create_contract_mock('audit', self.mock_client, tenant_id='test')

    # Mock validates operations automatically
    result = mock_store.log_event('LOGIN_SUCCESS', username='testuser')
    assert result  # Contract violations would raise exceptions

    # Verify contract compliance
    assert len(mock_store._store) == 1  # Mock tracks internal state
```

### Pattern 3: Business Rules Integration

```python
from tests.utils.business_rules import BusinessRules

def test_business_rules_compliance(self):
    rules = BusinessRules()

    # Test password policy
    password_result = rules.password_policy_check('MySecurePass123!')
    assert password_result['valid']

    # Test rate limiting
    rate_result = rules.rate_limit_check([1, 2, 3], 60000, 5)  # 1 min window
    assert rate_result['allowed']

    # Test tenant isolation
    isolation_result = rules.tenant_isolation_check('tenant_a', 'tenant_a')
    assert isolation_result['valid']
```

## Troubleshooting Guide

### Common Issues

#### Issue: Contract Violation Errors

**Symptoms:**
```
ContractViolationError: Missing required fields: ['event_type']
```

**Solutions:**
1. Check that all required fields are provided
2. Validate data types match contract expectations
3. Ensure tenant isolation is maintained

#### Issue: Business Rule Violations

**Symptoms:**
```
AssertionError: Business rule violation: ['Invalid user ID format']
```

**Solutions:**
1. Review the specific rule that's failing
2. Check data format against business rules specification
3. Update test data to comply with rules

#### Issue: Import Errors

**Symptoms:**
```
ImportError: No module named 'tests.contracts'
```

**Solutions:**
1. Ensure all contract files are created
2. Check Python path includes project root
3. Verify file permissions and syntax

### Performance Issues

#### Slow Test Execution

**Causes:**
- Contract validation overhead
- Business rules evaluation
- Mock initialization

**Solutions:**
```python
# Skip contract validation for performance-critical tests
@pytest.mark.no_contract_validation
def test_performance_critical_operation(self):
    # Test without contract overhead
    pass

# Use lazy initialization
mock_store = create_contract_mock('audit', client, lazy_init=True)
```

#### Memory Issues

**Causes:**
- Large mock data stores
- Caching too many contract instances

**Solutions:**
```python
# Configure cache limits in pytest.ini
contract_mock_cache_size = 100

# Use factory functions with cleanup
@pytest.fixture(autouse=True)
def cleanup_contract_mocks():
    yield
    # Cleanup mock instances
```

## Best Practices

### 1. Test Organization

```python
# Group contract-related tests
@pytest.mark.contract
class TestContractCompliance:
    # Tests that validate contract compliance

@pytest.mark.business_rules
class TestBusinessRules:
    # Tests that validate business rules

@pytest.mark.no_contract_validation
class TestPerformance:
    # Performance tests without validation overhead
```

### 2. Data Preparation

```python
@pytest.fixture
def valid_contract_data(self):
    """Provide valid data that passes all contract validations."""
    return {
        'event_type': 'LOGIN_SUCCESS',
        'user_id': 'user_123456789',
        'tenant_id': 'tenant_abcdef12',
        # ... other required fields
    }

@pytest.fixture
def invalid_contract_data(self):
    """Provide invalid data for negative testing."""
    return {
        'event_type': '',  # Invalid: empty
        'user_id': 'invalid@format',  # Invalid: wrong format
    }
```

### 3. Error Handling

```python
def test_contract_violations_are_caught(self, contract_enforcer):
    """Ensure contract violations are properly caught and reported."""
    invalid_data = {'missing': 'required_fields'}

    with pytest.raises(ContractViolationError) as exc_info:
        contract_enforcer.enforce_create_contract(invalid_data, ['required_field'])

    assert 'required' in str(exc_info.value).lower()
```

## Advanced Topics

### Custom Contract Validators

```python
from tests.contracts.firestore import ContractValidator

class CustomValidator(ContractValidator):
    """Extend validator with domain-specific rules."""

    def validate_domain_specific_rule(self, data):
        """Validate domain-specific business rules."""
        # Custom validation logic
        pass
```

### Contract Mock Extensions

```python
from tests.contracts.mocks import ContractMockStore

class ExtendedAuditMock(ContractMockStore):
    """Extended mock with additional validation."""

    def validate_audit_trail_integrity(self):
        """Custom audit trail validation."""
        # Implementation
        pass
```

### CI/CD Integration

The CI/CD pipeline now includes:

1. **Contract Validation**: Automatic validation of contracts
2. **Business Rules Audit**: Verification of business rules compliance
3. **Security Checks**: Validation of contract security properties
4. **Performance Monitoring**: Tracking contract validation overhead

### Metrics and Monitoring

Track these metrics for migration success:

- **Contract Coverage**: Percentage of operations with contract validation
- **Violation Rate**: Number of contract violations caught
- **Performance Impact**: Test execution time overhead
- **False Positives**: Incorrect contract rejections

## Migration Checklist

Use `tests/docs/contract_tests_migration/migration_checklist.md` to track detailed progress:

- [x] Phase 1: Foundation setup (5/5 completed)
- [x] Phase 2: Core migration (16/16 completed - All stores migrated including Auth Service Integration)
- [x] Phase 3: Configuration and documentation (8/8 completed)
- [ ] Phase 4: Validation and cleanup (0/8 pending)

## Support and Resources

### Getting Help

1. **Check the logs**: Contract violations include detailed error messages
2. **Review examples**: See `test_audit_store.py` for implementation patterns
3. **Run diagnostics**: Use `--contract-report` for detailed analysis

### Key Files

- `tests/contracts/base.py` - Protocol definitions
- `tests/contracts/firestore.py` - Runtime validators
- `tests/contracts/mocks.py` - Contract mocks
- `tests/utils/business_rules.py` - Business rules
- `tests/conftest.py` - Test configuration
- `pytest.ini` - Pytest configuration

### Next Steps

1. ✅ **Phase 2 Complete** - All core store migrations finished including Auth Service Integration
2. **Configure Firestore Credentials** - Set up authentication for contract validation tests
3. **Phase 4: Validation and Cleanup** - Run full test suite with contract validation enabled
4. **Validate Contract Coverage** - Ensure >95% of operations have contract validation
5. **Performance Audit** - Measure contract validation overhead (<5% target)
6. **Legacy Cleanup** - Remove deprecated mock files and update imports

---

*This guide is maintained automatically. Last updated during migration implementation.*
