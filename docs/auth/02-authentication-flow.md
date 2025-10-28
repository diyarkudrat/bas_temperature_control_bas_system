# Authentication Flow

## 🔄 How Authentication Works (Step by Step)

### Step 1: User Login
```
User → POST /auth/login → {"username": "john", "password": "secret123"}
                    ↓
            UserManager.authenticate_user()
                    ↓
            Check password hash + account status
                    ↓
            If valid: Create session
            If invalid: Increment failed attempts
```

### Step 2: Session Creation
```
Successful login → SessionManager.create_session()
                        ↓
                Generate secure token
                        ↓
                Create security fingerprint
                        ↓
                Store in database + memory cache
                        ↓
                Return session to user
```

### Step 3: Using Protected Endpoints (JWT preferred)
```
User request → @require_auth decorator
                    ↓
            Parse Authorization: Bearer <JWT>
                    ↓
            Verify & decode JWT with provider
                    ↓
            Role check (claims-only or provider metadata)
                    ↓
            If ok: Allow access
            If invalid & fallback disabled: 401
            If invalid & fallback enabled: try session
```

### Step 4: Session Fallback (if enabled)
```
Extract X-Session-ID header or bas_session_id cookie
        ↓
Validate via SessionManager.validate_session()
        ↓
Role check → optional tenant enforcement (X-BAS-Tenant)
        ↓
If valid: Allow access
If invalid: 401
```

### Step 5: Session Cleanup
```
Background thread → Clean up expired sessions
                        ↓
                Remove from database + cache
                        ↓
                Log cleanup events
```
