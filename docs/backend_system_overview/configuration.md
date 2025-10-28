# Configuration

The system uses a two-tier configuration approach.

## 1) System Configuration (`config.json`)
```json
{
  "current_profile": "default",
  "profiles": {
    "default": {
      "setpoint_tenths": 230,
      "deadband_tenths": 5,
      "sample_period_ms": 2000,
      "min_on_ms": 10000,
      "min_off_ms": 10000,
      "pin_ds18b20": 4,
      "pin_relay_cool": 15,
      "pin_relay_heat": 14,
      "relay_active_high": true,
      "cool_only": true,
      "heat_always_on": true
    }
  }
}
```

## 2) Secrets (`secrets.json`)
```json
{
  "wifi_ssid": "YOUR_WIFI_NETWORK_NAME",
  "wifi_password": "YOUR_WIFI_PASSWORD",
  "api_token": "your-secure-api-token-here"
}
```

## Profiles
- `default` — standard setup
- `production` — high-reliability
- `debug` — development/testing
