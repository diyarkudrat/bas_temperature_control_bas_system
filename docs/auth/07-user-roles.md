# User Roles

## 👥 User Roles Explained

### Role Hierarchy
```
Admin (Level 3)
├── Can manage users
├── Can access all endpoints
└── Full system control

Operator (Level 2)
├── Can control temperature
├── Can view telemetry
└── Cannot manage users

Read-Only (Level 1)
├── Can view status/telemetry
└── Cannot change anything
```

### Permission Checking
```python
@require_auth(required_role="admin")      # Only admins
@require_auth(required_role="operator")   # Admins + operators
@require_auth(required_role="read-only")  # Everyone
```
