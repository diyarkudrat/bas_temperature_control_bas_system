## 🔐 Auth0 → Flask Backend Authentication Flow

```mermaid
sequenceDiagram
    autonumber

    participant Client as API Client (Frontend / Postman)
    participant Flask as Flask Backend (Python)
    participant JWKS as Auth0 JWKS Endpoint
    participant DB as Internal Service / Database

    Note over Client,Flask: Request to protected backend API

    Client->>Flask: 1️⃣ HTTP Request with<br/>Authorization: Bearer &lt;JWT&gt;

    Note right of Flask: Extract JWT header & claims

    Flask->>JWKS: 2️⃣ Fetch JWKS keys (cached)<br/>GET /.well-known/jwks.json
    JWKS-->>Flask: 3️⃣ Return public keys (RS256)

    Note right of Flask: Select matching `kid`, verify signature

    Flask->>Flask: 4️⃣ Validate claims<br/>iss, aud, exp, nbf, iat

    alt Valid token
        Flask->>Flask: 5️⃣ Enforce scopes / permissions
        Flask->>DB: 6️⃣ Execute business logic<br/>(e.g., query data)
        DB-->>Flask: 7️⃣ Return data
        Flask-->>Client: ✅ 200 OK<br/>Authorized response
    else Invalid token
        Flask-->>Client: ❌ 401 Unauthorized<br/>Invalid or expired JWT
    end

| Step | Backend Component      | Description                                      |
| ---- | ---------------------- | ------------------------------------------------ |
| 1️⃣  | Flask API endpoint     | Receives `Authorization: Bearer <JWT>` header.   |
| 2️⃣  | JWKS fetch             | Downloads or retrieves cached Auth0 public keys. |
| 3️⃣  | Signature verification | Validates JWT signature using RS256 key.         |
| 4️⃣  | Claim validation       | Checks `iss`, `aud`, `exp`, `nbf`, and `iat`.    |
| 5️⃣  | Scope enforcement      | Confirms scopes/roles required for route.        |
| 6️⃣  | Business logic         | Executes internal logic if authorized.           |
| 7️⃣  | Response               | Returns data (200 OK) or error (401/403).        |

