# Authentication System Overview

## 🎯 Quick Summary

The BAS authentication system supports **JWT (preferred)** and **session tokens (fallback)** with role-based access control. It’s a modern web app auth model adapted for an IoT controller.

**In simple terms**: Clients call protected endpoints using `Authorization: Bearer <JWT>`. If configured, a user can also login with username/password to obtain a secure session token used via `X-Session-ID` header or `bas_session_id` cookie.

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
