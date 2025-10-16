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

### Step 3: Using Protected Endpoints
```
User request → @require_auth decorator
                    ↓
            Extract session token from header/cookie
                    ↓
            SessionManager.validate_session()
                    ↓
            Check: valid? expired? fingerprint match?
                    ↓
            If valid: Allow access
            If invalid: Return 401 error
```

### Step 4: Session Cleanup
```
Background thread → Clean up expired sessions
                        ↓
                Remove from database + cache
                        ↓
                Log cleanup events
```
