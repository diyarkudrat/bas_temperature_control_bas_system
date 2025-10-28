# Architecture

```
┌─────────────────┐    WiFi    ┌─────────────────┐
│   Your Computer │◄─────────►│   Raspberry Pi  │
│   (Full Server) │           │   Pico W        │
│                 │           │   (Minimal)     │
│ • Web Interface │           │ • Temperature   │
│ • Control Logic │           │   Sensor        │
│ • Database      │           │ • Relays        │
│ • Telemetry     │           │ • Basic I/O     │
└─────────────────┘           └─────────────────┘
```

### Key Backend Components
- Server entrypoint: `apps/api/main.py` (Flask, DI composition)
- HTTP APIs under `apps/api/http/*` (routes, middleware)
- Auth: JWT via provider (Auth0/Mock) with session fallback
- Data: Firestore repositories (`adapters/db/firestore/*`) with emulator-first local dev
- Caching & limits: request limiter, per-user Redis sliding window, revocation cache

### Simple Module Layout (embedded)
```
┌──────────────────────────────────────────────┐
│  main.py (SystemOrchestrator)                │
│  ┌──────────┐  ┌─────────┐  ┌────────────┐  │
│  │Controller│  │ Display │  │ API Server │  │
│  └──────────┘  └─────────┘  └────────────┘  │
└──────────────────────────────────────────────┘
         │              │              │
┌────────┴──────────────┴──────────────┴───────┐
│  interfaces/ (Sensor, Actuator, Clock)       │
└──────────────────────────────────────────────┘
         │              │              │
┌────────┴──────────────┴──────────────┴───────┐
│  src/bas/hardware/ (DS18B20, Relay, SystemClock) │
└──────────────────────────────────────────────┘
```
