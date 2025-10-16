# Implementation Details

## 🛠️ For Engineers: Key Implementation Details

### Session Fingerprinting
```python
def create_session_fingerprint(user_agent, accept_language, accept_encoding, ip_address):
    """Creates a unique fingerprint for the user's browser/device."""
    components = [user_agent, accept_language, accept_encoding, ip_address]
    fingerprint_data = '|'.join(components)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()
```
**Why**: Prevents session hijacking by ensuring sessions can't be used from different devices.

### Rate Limiting Logic
```python
def is_allowed(ip, username=None):
    """Check if request is within rate limits."""
    # Check IP lockout
    if ip in lockouts and time.time() < lockouts[ip]:
        return False, "IP temporarily locked"
    
    # Check user-specific limits
    if username and attempts_count(ip, username) >= max_attempts:
        lockouts[ip] = time.time() + lockout_duration
        return False, "Too many failed attempts"
    
    return True, "Allowed"
```

### Password Hashing
```python
def hash_password(password, salt=None):
    """Hash password using PBKDF2-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(32)  # 256-bit random salt
    
    # 100,000 iterations for security
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return password_hash.hex(), salt.hex()
```

### Session Validation
```python
def validate_session(session_id, request):
    """Validate session and check security fingerprint."""
    session = get_session(session_id)
    
    # Check expiration
    if session.is_expired():
        return None
    
    # Check fingerprint (prevents hijacking)
    current_fingerprint = create_session_fingerprint(
        request.headers.get('User-Agent'),
        request.headers.get('Accept-Language'),
        request.headers.get('Accept-Encoding'),
        request.remote_addr
    )
    
    if session.fingerprint != current_fingerprint:
        return None  # Potential hijacking attempt
    
    return session
```
