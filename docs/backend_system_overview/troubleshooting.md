# Troubleshooting

## Common Issues

| Issue | Solution |
|-------|----------|
| Pico W not found | Check USB connection, try BOOTSEL mode |
| WiFi connection fails | Verify credentials in `pico_client.py` |
| Server won't start | Run `cd server && ./setup_server.sh` |
| No data from Pico | Check IP address in SERVER_URL |
| Dashboard not loading | Ensure server running on port 8080 |

## Debug Commands
```bash
# Check Pico W connection
mpremote connect /dev/cu.usbmodem* exec "import network; print(network.WLAN().ifconfig())"

# Check server logs
cd server && source venv/bin/activate && python3 bas_server.py

# Test API
curl http://localhost:8080/api/health
```
