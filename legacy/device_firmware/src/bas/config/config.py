# config/config.py
# This file is intentionally empty to avoid committing sensitive configuration data.
# 
# The system uses a two-tier configuration approach:
# 1. secrets.json - Contains sensitive data (WiFi credentials, API tokens) - NOT committed to git
# 2. config.json - Contains non-sensitive system configuration - committed to git
#
# For local development, create a secrets.json file in the project root with:
# {
#   "wifi_ssid": "YOUR_WIFI_NETWORK_NAME",
#   "wifi_password": "YOUR_WIFI_PASSWORD", 
#   "api_token": "your-secure-api-token-here"
# }
#
# The system will automatically load secrets from this file if present,
# falling back to hardcoded values in config.py if needed.
