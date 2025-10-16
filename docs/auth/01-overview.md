# Authentication System Overview

## 🎯 Quick Summary

The BAS authentication system is a **session-based authentication system** with role-based access control. Think of it as a modern web application authentication system adapted for an IoT temperature controller.

**In simple terms**: Users log in with username/password, get a secure session token, and use that token to access protected endpoints. The system tracks who's doing what and when.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication System                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
│  │   Users     │  │  Sessions   │  │   Security  │  │  Audit   │ │
│  │             │  │             │  │             │  │          │ │
│  │ • Login     │  │ • Tokens    │  │ • Rate Limit│  │ • Logs   │ │
│  │ • Password  │  │ • Expiry    │  │ • Headers   │  │ • Events │ │
│  │ • Roles     │  │ • Security  │  │ • Validation│  │ • Access │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                    │
                            ┌───────▼───────┐
                            │   Flask App   │
                            │   Middleware  │
                            └───────────────┘
```

---

## 🧩 Core Components Explained

### 1. **User Management** (`UserManager`)
**What it does**: Handles user accounts, passwords, and authentication.

**Key responsibilities**:
- Store user accounts with hashed passwords
- Validate login credentials
- Track failed login attempts
- Lock accounts after too many failures

**How it works**:
```python
# User tries to log in
user = user_manager.authenticate_user(username, password)

# System checks:
# 1. Does user exist?
# 2. Is password correct?
# 3. Is account locked?
# 4. Update login time
```

### 2. **Session Management** (`SessionManager`)
**What it does**: Creates, validates, and manages user sessions.

**Key responsibilities**:
- Generate secure session tokens
- Track active sessions
- Validate session fingerprints (prevents hijacking)
- Clean up expired sessions

**How it works**:
```python
# After successful login
session = session_manager.create_session(username, role, request)

# Session contains:
# - Unique token (like a temporary ID card)
# - User info and permissions
# - Security fingerprint (browser/device signature)
# - Expiration time
```

### 3. **Security Layer** (`RateLimiter` + Security Headers)
**What it does**: Protects against attacks and enforces security policies.

**Key responsibilities**:
- Block IPs after too many failed attempts
- Add security headers to responses
- Validate session fingerprints
- Enforce password strength

### 4. **Audit System** (`AuditLogger`)
**What it does**: Tracks everything that happens for security monitoring.

**What it logs**:
- Login attempts (success/failure)
- Session creation/destruction
- Access to protected endpoints
- Security events
