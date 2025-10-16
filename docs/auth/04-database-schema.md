# Database Schema

## 📊 Database Schema

### Users Table
```sql
CREATE TABLE users (
    username TEXT PRIMARY KEY,           -- User's login name
    password_hash TEXT NOT NULL,         -- PBKDF2-SHA256 hash
    salt TEXT NOT NULL,                  -- Unique salt per user
    role TEXT NOT NULL DEFAULT 'operator', -- 'admin', 'operator', 'read-only'
    created_at REAL NOT NULL,            -- Account creation timestamp
    last_login REAL DEFAULT 0,           -- Last successful login
    failed_attempts INTEGER DEFAULT 0,   -- Current failed attempt count
    locked_until REAL DEFAULT 0,         -- Lockout expiration time
    password_history TEXT DEFAULT '[]'   -- JSON array of old password hashes
);
```

### Sessions Table
```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,         -- Unique session token
    username TEXT NOT NULL,              -- Who owns this session
    role TEXT NOT NULL,                  -- User's role (cached for performance)
    created_at REAL NOT NULL,            -- Session creation time
    expires_at REAL NOT NULL,            -- Session expiration time
    last_access REAL NOT NULL,           -- Last activity timestamp
    fingerprint TEXT NOT NULL,           -- Security fingerprint
    ip_address TEXT NOT NULL,            -- Client IP address
    user_agent TEXT NOT NULL,            -- Browser/client info
    FOREIGN KEY (username) REFERENCES users (username)
);
```

### Audit Log Table
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,             -- When the event happened
    username TEXT,                       -- Who did it (if known)
    ip_address TEXT,                     -- Where it came from
    action TEXT NOT NULL,                -- What happened
    endpoint TEXT,                       -- Which API endpoint
    success BOOLEAN NOT NULL,            -- Did it succeed?
    details TEXT DEFAULT '{}'            -- Additional context (JSON)
);
```
