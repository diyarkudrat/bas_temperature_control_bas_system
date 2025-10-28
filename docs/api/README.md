# BAS System API Reference

**Complete API documentation for the Building Automation System (BAS) temperature controller.**

## 📋 Table of Contents

| Section | File | Description |
|---------|------|-------------|
| 🌐 **Overview** | [01-overview.md](01-overview.md) | Base URL, authentication, and system status APIs |
| ⚙️ **Control APIs** | [02-control-apis.md](02-control-apis.md) | Temperature control and sensor data endpoints |
| 📋 **Configuration** | [03-configuration-apis.md](03-configuration-apis.md) | System configuration endpoints |
| 📈 **Telemetry** | [04-telemetry-apis.md](04-telemetry-apis.md) | Time-series data endpoints |
| 🌐 **Web Dashboard** | [05-web-dashboard.md](05-web-dashboard.md) | Web interface documentation |
| 📊 **Error Codes** | [06-error-codes.md](06-error-codes.md) | Error handling and troubleshooting |
| 📱 **Client Examples** | [07-client-examples.md](07-client-examples.md) | Code examples in multiple languages |
| 🔐 **Authentication APIs** | [../auth/06-api-endpoints.md](../auth/06-api-endpoints.md) | Authentication and protected endpoints |

---

## 🔐 Authentication APIs

The BAS system includes a comprehensive authentication system with session-based security:

### **Authentication Endpoints**
- **`POST /auth/login`** - User login with username/password
- **`POST /auth/logout`** - End user session  
- **`GET /auth/status`** - Check session validity

### **Protected Endpoints**
- **`POST /api/set_setpoint`** - Set temperature setpoint (requires operator+ role)
- **`GET /api/telemetry`** - Access telemetry data (requires read-only+ role)

### **User Roles**
- **Admin** - Full system control and user management
- **Operator** - Temperature control and telemetry access
- **Read-Only** - View-only access to system data

📚 **Complete Authentication API Documentation**: See [Authentication API Endpoints](../auth/06-api-endpoints.md) for detailed authentication endpoints, request/response formats, and protected endpoint usage. Also see health: `GET /api/health` (public) and `GET /api/health/auth` (auth provider status).

📚 **Complete Authentication System Documentation**: See [Authentication Documentation](../auth/README.md) for detailed authentication system design, security features, user management, and implementation details.

---

## 🚀 Quick Start

**New to the API?** Start with:
1. [01-overview.md](01-overview.md) - Understand the base URL and system status
2. [02-control-apis.md](02-control-apis.md) - Learn how to control temperature
3. [07-client-examples.md](07-client-examples.md) - See working code examples

**Need authentication?** Check:
1. [Authentication Overview](../auth/01-overview.md) - Authentication system overview
2. [Authentication API Endpoints](../auth/06-api-endpoints.md) - Auth-specific endpoints
3. [Authentication Testing](../auth/10-testing.md) - Auth testing examples

**Having issues?** See:
1. [06-error-codes.md](06-error-codes.md) - Common errors and solutions
2. [Authentication Troubleshooting](../auth/09-troubleshooting.md) - Auth-specific issues

---

## 📁 File Structure

```
docs/api/
├── README.md                           # This index file
├── 01-overview.md                      # Base URL, auth, and system status
├── 02-control-apis.md                  # Temperature control endpoints
├── 03-configuration-apis.md           # System configuration
├── 04-telemetry-apis.md               # Time-series data
├── 05-web-dashboard.md                # Web interface
├── 06-error-codes.md                  # Error handling
└── 07-client-examples.md              # Code examples
```

---

## 🔗 Related Documentation

- [../auth/README.md](../auth/README.md) - Complete authentication system documentation
- [../SYSTEM_OVERVIEW.md](../SYSTEM_OVERVIEW.md) - Overall system architecture
- [../../server/auth/AUTH_SETUP_GUIDE.md](../../server/auth/AUTH_SETUP_GUIDE.md) - Auth setup and installation guide
