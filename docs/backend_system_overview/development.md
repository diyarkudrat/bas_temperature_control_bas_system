# Development

## Deploy & Monitor
```bash
./deploy              # Deploy to Pico (auto-detects device)
./monitor             # Real-time output
./status              # Quick health check
scripts/repl.sh       # Interactive Python
```

## Testing
```bash
# On Pico (via REPL)
import tests.test_runner as t
t.main()

# From computer
python3 tools/test_api.py
```

## Debugging
```bash
scripts/wifi_debug.sh      # WiFi diagnostics
scripts/verify.sh          # Verify installation
```
