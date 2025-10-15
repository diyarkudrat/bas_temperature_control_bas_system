# netctrl/api.py
# Production-grade HTTP API server with security, validation, and non-blocking patterns

import ujson as json
import uselect as select
import usocket as socket
import utime as time
try:
    import uhashlib as hashlib
    import ubinascii
    _has_uhashlib = True
except ImportError:
    import hashlib
    _has_uhashlib = False
try:
    import urandom as random
except ImportError:
    import random
from services import Logger, LoggerFactory, SystemError, SystemErrorCodes

class HTTPRequest:
    """Parsed HTTP request with validation."""
    
    def __init__(self):
        self.method: str = ""
        self.path: str = ""
        self.query_params: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.body: bytes = b""
        self.client_ip: str = ""
        self.timestamp_ms: int = 0
        self.content_length: int = 0
        self.is_valid: bool = False

class HTTPResponse:
    """HTTP response builder."""
    
    def __init__(self, status_code: int = 200, status_text: str = "OK"):
        self.status_code = status_code
        self.status_text = status_text
        self.headers: Dict[str, str] = {
            'Connection': 'close',
            'Cache-Control': 'no-cache'
        }
        self.body: bytes = b""
    
    def set_json(self, data: Any) -> None:
        """Set JSON response body."""
        self.body = json.dumps(data).encode('utf-8')
        self.headers['Content-Type'] = 'application/json'
        self.headers['Content-Length'] = str(len(self.body))
    
    def set_text(self, text: str) -> None:
        """Set plain text response body."""
        self.body = text.encode('utf-8')
        self.headers['Content-Type'] = 'text/plain'
        self.headers['Content-Length'] = str(len(self.body))
    
    def set_html(self, html: str) -> None:
        """Set HTML response body."""
        self.body = html.encode('utf-8')
        self.headers['Content-Type'] = 'text/html; charset=utf-8'
        self.headers['Content-Length'] = str(len(self.body))
    
    def to_bytes(self) -> bytes:
        """Convert response to HTTP bytes."""
        status_line = f"HTTP/1.1 {self.status_code} {self.status_text}\r\n"
        
        header_lines = []
        for key, value in self.headers.items():
            header_lines.append(f"{key}: {value}\r\n")
        
        response = status_line + ''.join(header_lines) + "\r\n"
        return response.encode('utf-8') + self.body

class RateLimiter:
    """Simple rate limiter to prevent DoS attacks."""
    
    def __init__(self, max_requests=10, window_ms=60000):
        self.max_requests = max_requests
        self.window_ms = window_ms
        self._requests = {}  # ip -> timestamps
    
    def is_allowed(self, client_ip: str) -> bool:
        """Check if request from client IP is allowed."""
        current_time = time.ticks_ms()
        
        if client_ip not in self._requests:
            self._requests[client_ip] = []
        
        # Clean old requests outside window
        requests = self._requests[client_ip]
        self._requests[client_ip] = [
            timestamp for timestamp in requests
            if time.ticks_diff(current_time, timestamp) <= self.window_ms
        ]
        
        # Check if under limit
        if len(self._requests[client_ip]) < self.max_requests:
            self._requests[client_ip].append(current_time)
            return True
        
        return False

class AuthManager:
    """Simple token-based authentication with timing-safe comparison."""
    
    def __init__(self, valid_tokens):
        # Hash tokens to avoid storing in plain text
        self._token_hashes = set()
        for token in valid_tokens:
            token_hash = self._hash_token(token)
            self._token_hashes.add(token_hash)
    
    def _hash_token(self, token):
        """Hash token with salt."""
        salt = b"bas_controller_salt"  # Simple salt for MicroPython
        h = hashlib.sha256(salt + token.encode('utf-8'))
        
        # MicroPython uses digest() + ubinascii.hexlify(), CPython uses hexdigest()
        if _has_uhashlib:
            return ubinascii.hexlify(h.digest()).decode('ascii')
        else:
            return h.hexdigest()
    
    def is_valid_token(self, token: str) -> bool:
        """Timing-safe token validation."""
        if not token:
            return False
        
        provided_hash = self._hash_token(token)
        
        # Compare against all valid hashes (timing-safe)
        is_valid = False
        for valid_hash in self._token_hashes:
            if self._constant_time_compare(provided_hash, valid_hash):
                is_valid = True
                # Don't break early to maintain constant time
        
        return is_valid
    
    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0

class ClientConnection:
    """Manages individual client connection state."""
    
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.client_ip = addr[0]
        self.request_buffer = b""
        self.response_queue = []
        self.last_activity_ms = time.ticks_ms()
        self.is_sse_client = False
        self.is_closing = False
    
    def is_expired(self, timeout_ms: int) -> bool:
        """Check if connection has timed out."""
        return time.ticks_diff(time.ticks_ms(), self.last_activity_ms) > timeout_ms
    
    def close(self) -> None:
        """Close connection safely."""
        if not self.is_closing:
            self.is_closing = True
            try:
                self.conn.close()
            except:
                pass

class HardenedApiServer:
    """Production-hardened HTTP API server with security features."""
    
    # Security limits
    MAX_REQUEST_SIZE = 8192      # 8KB max request
    MAX_HEADER_SIZE = 2048       # 2KB max headers
    MAX_CLIENTS = 5              # Max concurrent connections
    CLIENT_TIMEOUT_MS = 30000    # 30s client timeout
    REQUEST_TIMEOUT_MS = 5000    # 5s per request
    MAX_SSE_CLIENTS = 3          # Max SSE connections
    
    def __init__(self, controller, config_manager, auth_tokens):
        self.controller = controller
        self.config = config_manager
        self._logger = LoggerFactory.get_logger("ApiServer")
        
        # Security components (generous limits for development/testing)
        self._rate_limiter = RateLimiter(max_requests=100, window_ms=60000)
        self._auth = AuthManager(auth_tokens)
        
        # Connection management
        self._clients = {}
        self._server_socket = None
        self._running = False
        
        # Route handlers
        self._routes = {}
        self._init_routes()
    
    def _init_routes(self) -> None:
        """Initialize route handlers."""
        self._routes = {
            'GET /': self._handle_dashboard,
            'GET /status': self._handle_status,
            'POST /set': self._handle_set_config,
            'GET /events': self._handle_events,
            'GET /logs': self._handle_logs,
            'GET /config': self._handle_get_config,
            'POST /config/profile': self._handle_set_profile,
        }
    
    def start(self, host="0.0.0.0", port=80):
        """Start the server."""
        try:
            self._server_socket = socket.socket()
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((host, port))
            self._server_socket.listen(self.MAX_CLIENTS)
            
            # Set non-blocking mode
            self._server_socket.setblocking(False)
            
            self._running = True
            self._logger.info("Server started", host=host, port=port)
            return True
            
        except Exception as e:
            handle_error(
                SystemErrorCodes.NETWORK_CONNECTION_FAILED,
                f"Failed to start server: {e}",
                "ApiServer"
            )
            return False
    
    def stop(self) -> None:
        """Stop the server and close all connections."""
        self._running = False
        
        # Close all client connections
        for client in self._clients.values():
            client.close()
        self._clients.clear()
        
        # Close server socket
        if self._server_socket:
            try:
                self._server_socket.close()
            except:
                pass
            self._server_socket = None
        
        self._logger.info("Server stopped")
    
    def process_events(self, timeout_ms=100):
        """Process network events (non-blocking main loop integration)."""
        if not self._running or not self._server_socket:
            return
        
        try:
            # Check for new connections and data
            readable, writable, error = select.select(
                [self._server_socket] + list(self._clients.keys()),
                [sock for sock, client in self._clients.items() if client.response_queue],
                list(self._clients.keys()),
                timeout_ms / 1000.0
            )
            
            # Handle new connections
            if self._server_socket in readable:
                self._accept_connection()
            
            # Handle client data
            for sock in readable:
                if sock != self._server_socket:
                    self._handle_client_data(sock)
            
            # Send responses
            for sock in writable:
                self._send_response(sock)
            
            # Handle errors and cleanup
            for sock in error:
                self._cleanup_client(sock)
            
            # Cleanup expired clients
            self._cleanup_expired_clients()
            
            # Broadcast SSE events
            self._broadcast_sse_events()
            
        except Exception as e:
            self._logger.error("Error processing network events", error=str(e))
    
    def _accept_connection(self) -> None:
        """Accept new client connection."""
        try:
            if len(self._clients) >= self.MAX_CLIENTS:
                # Reject connection - too many clients
                conn, addr = self._server_socket.accept()
                conn.close()
                self._logger.warning("Connection rejected - too many clients", client_ip=addr[0])
                return
            
            conn, addr = self._server_socket.accept()
            conn.setblocking(False)
            
            # Rate limiting check
            if not self._rate_limiter.is_allowed(addr[0]):
                conn.close()
                self._logger.warning("Connection rejected - rate limited", client_ip=addr[0])
                return
            
            # Create client connection
            client = ClientConnection(conn, addr)
            self._clients[conn] = client
            
            self._logger.debug("New client connected", client_ip=addr[0], total_clients=len(self._clients))
            
        except Exception as e:
            self._logger.error("Error accepting connection", error=str(e))
    
    def _handle_client_data(self, sock: socket.socket) -> None:
        """Handle incoming data from client."""
        if sock not in self._clients:
            return
        
        client = self._clients[sock]
        
        try:
            # Read data with size limit
            remaining_size = self.MAX_REQUEST_SIZE - len(client.request_buffer)
            if remaining_size <= 0:
                self._send_error_response(client, 413, "Request Entity Too Large")
                return
            
            data = sock.recv(min(1024, remaining_size))
            if not data:
                # Client disconnected
                self._cleanup_client(sock)
                return
            
            client.request_buffer += data
            client.last_activity_ms = time.ticks_ms()
            
            # Try to parse complete request
            if b"\r\n\r\n" in client.request_buffer:
                self._process_request(client)
                
        except Exception as e:
            self._logger.error("Error handling client data", client_ip=client.client_ip, error=str(e))
            self._cleanup_client(sock)
    
    def _process_request(self, client: ClientConnection) -> None:
        """Process complete HTTP request."""
        try:
            request = self._parse_request(client.request_buffer, client.client_ip)
            client.request_buffer = b""  # Clear buffer
            
            if not request.is_valid:
                self._send_error_response(client, 400, "Bad Request")
                return
            
            # Find route handler
            route_key = f"{request.method} {request.path.split('?')[0]}"
            if route_key not in self._routes:
                self._send_error_response(client, 404, "Not Found")
                return
            
            # Execute handler
            handler = self._routes[route_key]
            response = handler(request)
            
            # Queue response
            client.response_queue.append(response)
            
        except Exception as e:
            self._logger.error("Error processing request", client_ip=client.client_ip, error=str(e))
            self._send_error_response(client, 500, "Internal Server Error")
    
    def _parse_request(self, data: bytes, client_ip: str) -> HTTPRequest:
        """Parse HTTP request with validation."""
        request = HTTPRequest()
        request.client_ip = client_ip
        request.timestamp_ms = time.ticks_ms()
        
        try:
            # Split headers and body
            if b"\r\n\r\n" not in data:
                return request
            
            headers_data, body_data = data.split(b"\r\n\r\n", 1)
            headers_text = headers_data.decode('utf-8', 'ignore')
            
            # Parse request line
            lines = headers_text.split('\r\n')
            if not lines:
                return request
            
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) != 3:
                return request
            
            request.method, full_path, _ = parts
            
            # Parse path and query params
            if '?' in full_path:
                request.path, query_string = full_path.split('?', 1)
                request.query_params = self._parse_query_string(query_string)
            else:
                request.path = full_path
            
            # Parse headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    request.headers[key.strip().lower()] = value.strip()
            
            # Handle body based on content-length
            content_length = int(request.headers.get('content-length', '0'))
            if content_length > 0:
                if content_length > self.MAX_REQUEST_SIZE:
                    return request  # Too large
                request.content_length = content_length
                request.body = body_data[:content_length]
            
            request.is_valid = True
            
        except Exception as e:
            self._logger.warning("Request parsing failed", client_ip=client_ip, error=str(e))
        
        return request
    
    def _parse_query_string(self, query_string):
        """Parse URL query string."""
        params = {}
        for pair in query_string.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
        return params
    
    # Route handlers
    def _handle_dashboard(self, request: HTTPRequest) -> HTTPResponse:
        """Serve minimal dashboard."""
        html = """<!DOCTYPE html>
<html><head><title>BAS Controller</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: system-ui, sans-serif; margin: 20px; max-width: 600px; }
.status { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 20px 0; }
.card { border: 1px solid #ccc; padding: 15px; border-radius: 5px; }
.alarm { background-color: #ffebee; border-color: #f44336; }
input, button { padding: 8px; margin: 5px; }
button { background: #2196f3; color: white; border: none; cursor: pointer; }
</style></head>
<body>
<h1>BAS Temperature Controller</h1>
<div class="status">
  <div class="card">
    <h3>Current Status</h3>
    <div>Temperature: <span id="temp">--</span>°C</div>
    <div>Setpoint: <span id="setpoint">--</span>°C</div>
    <div>State: <span id="state">--</span></div>
  </div>
  <div class="card">
    <h3>Actuators</h3>
    <div>Cooling: <span id="cooling">--</span></div>
    <div>Heating: <span id="heating">--</span></div>
  </div>
</div>
<div class="card" id="alarm" style="display:none;">
  <h3>⚠️ System Alarm</h3>
  <div id="alarm-msg">Sensor fault detected</div>
</div>
<div class="card">
  <h3>Controls</h3>
  <input type="number" id="new-sp" placeholder="Setpoint (°C)" step="0.1">
  <button onclick="updateSetpoint()">Update Setpoint</button>
</div>
<script>
async function updateStatus() {
  try {
    const response = await fetch('/status');
    const data = await response.json();
    
    document.getElementById('temp').textContent = 
      data.temp_tenths ? (data.temp_tenths/10).toFixed(1) : '--';
    document.getElementById('setpoint').textContent = (data.setpoint_tenths/10).toFixed(1);
    document.getElementById('state').textContent = data.state;
    document.getElementById('cooling').textContent = data.cool_active ? 'ON' : 'OFF';
    document.getElementById('heating').textContent = data.heat_active ? 'ON' : 'OFF';
    
    const alarm = document.getElementById('alarm');
    if (data.alarm) {
      alarm.style.display = 'block';
      alarm.className = 'card alarm';
    } else {
      alarm.style.display = 'none';
    }
  } catch (e) {
    console.error('Failed to fetch status:', e);
  }
}

async function updateSetpoint() {
  const newSp = document.getElementById('new-sp').value;
  if (!newSp) return;
  
  const token = prompt('Enter API token:');
  if (!token) return;
  
  try {
    const response = await fetch(`/set?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sp: Math.round(parseFloat(newSp) * 10) })
    });
    
    if (response.ok) {
      alert('Setpoint updated successfully');
      updateStatus();
    } else {
      alert('Failed to update setpoint: ' + await response.text());
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// Update every 2 seconds
setInterval(updateStatus, 2000);
updateStatus();
</script>
</body></html>"""
        
        response = HTTPResponse()
        response.set_html(html)
        return response
    
    def _handle_status(self, request: HTTPRequest) -> HTTPResponse:
        """Return current system status."""
        status = self.controller.last_status
        
        if not status:
            response = HTTPResponse(503, "Service Unavailable")
            response.set_json({"error": "Controller not ready"})
            return response
        
        # Convert to API format
        api_status = {
            "state": status.state,
            "temp_tenths": status.temp_tenths,
            "setpoint_tenths": status.setpoint_tenths,
            "deadband_tenths": status.deadband_tenths,
            "cool_active": status.cool_active,
            "heat_active": status.heat_active,
            "alarm": status.alarm,
            "sensor_ok": status.sensor_ok,
            "error_code": status.error_code,
            "timestamp_ms": time.ticks_ms()
        }
        
        response = HTTPResponse()
        response.set_json(api_status)
        return response
    
    def _handle_set_config(self, request: HTTPRequest) -> HTTPResponse:
        """Handle configuration updates (requires authentication)."""
        # Check authentication
        token = request.query_params.get('token', '')
        if not self._auth.is_valid_token(token):
            response = HTTPResponse(403, "Forbidden")
            response.set_json({"error": "Invalid or missing token"})
            return response
        
        try:
            # Parse JSON body
            if not request.body:
                raise ValueError("Empty request body")
            
            data = json.loads(request.body.decode('utf-8'))
            
            # Update controller parameters
            updated = {}
            if 'sp' in data:
                self.controller.set_setpoint_tenths(int(data['sp']))
                updated['setpoint_tenths'] = int(data['sp'])
            
            if 'db' in data:
                self.controller.set_deadband_tenths(int(data['db']))
                updated['deadband_tenths'] = int(data['db'])
            
            self._logger.info("Configuration updated via API", 
                            client_ip=request.client_ip, updated=updated)
            
            response = HTTPResponse()
            response.set_json({"status": "success", "updated": updated})
            return response
            
        except Exception as e:
            response = HTTPResponse(400, "Bad Request")
            response.set_json({"error": f"Invalid request: {e}"})
            return response
    
    def _handle_events(self, request: HTTPRequest) -> HTTPResponse:
        """Handle Server-Sent Events connection."""
        # Check if we have too many SSE clients
        sse_clients = sum(1 for client in self._clients.values() if client.is_sse_client)
        if sse_clients >= self.MAX_SSE_CLIENTS:
            response = HTTPResponse(503, "Service Unavailable")
            response.set_text("Too many SSE connections")
            return response
        
        # Mark client as SSE
        client = None
        for c in self._clients.values():
            if c.client_ip == request.client_ip:
                client = c
                break
        
        if client:
            client.is_sse_client = True
        
        # Return SSE headers
        response = HTTPResponse()
        response.headers.update({
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        })
        response.body = b"data: {\"event\": \"connected\"}\n\n"
        
        return response
    
    def _handle_logs(self, request: HTTPRequest) -> HTTPResponse:
        """Return recent system logs (requires authentication)."""
        token = request.query_params.get('token', '')
        if not self._auth.is_valid_token(token):
            response = HTTPResponse(403, "Forbidden") 
            response.set_json({"error": "Authentication required"})
            return response
        
        try:
            # Get logs from logger
            logger = LoggerFactory.get_logger("System")
            recent_logs = logger.get_recent_logs(50)
            
            log_data = []
            for entry in recent_logs:
                log_data.append({
                    "timestamp_ms": entry.timestamp_ms,
                    "level": entry.level,
                    "component": entry.component,
                    "message": entry.message,
                    "data": entry.data
                })
            
            response = HTTPResponse()
            response.set_json({"logs": log_data})
            return response
            
        except Exception as e:
            response = HTTPResponse(500, "Internal Server Error")
            response.set_json({"error": str(e)})
            return response
    
    def _handle_get_config(self, request: HTTPRequest) -> HTTPResponse:
        """Return current configuration summary."""
        try:
            summary = self.config.get_profile_summary()
            response = HTTPResponse()
            response.set_json(summary)
            return response
        except Exception as e:
            response = HTTPResponse(500, "Internal Server Error")
            response.set_json({"error": str(e)})
            return response
    
    def _handle_set_profile(self, request: HTTPRequest) -> HTTPResponse:
        """Switch configuration profile (requires authentication)."""
        token = request.query_params.get('token', '')
        if not self._auth.is_valid_token(token):
            response = HTTPResponse(403, "Forbidden")
            response.set_json({"error": "Authentication required"})
            return response
        
        try:
            data = json.loads(request.body.decode('utf-8'))
            profile_name = data.get('profile')
            
            if not profile_name:
                raise ValueError("Profile name required")
            
            if self.config.set_profile(profile_name):
                self._logger.info("Profile switched via API", 
                                profile=profile_name, client_ip=request.client_ip)
                response = HTTPResponse()
                response.set_json({"status": "success", "profile": profile_name})
            else:
                response = HTTPResponse(400, "Bad Request")
                response.set_json({"error": "Invalid profile name"})
            
            return response
            
        except Exception as e:
            response = HTTPResponse(400, "Bad Request")
            response.set_json({"error": str(e)})
            return response
    
    def _send_response(self, sock: socket.socket) -> None:
        """Send queued response to client."""
        if sock not in self._clients:
            return
        
        client = self._clients[sock]
        if not client.response_queue:
            return
        
        try:
            response = client.response_queue[0]
            response_bytes = response.to_bytes()
            
            sent = sock.send(response_bytes)
            if sent == len(response_bytes):
                # Complete response sent
                client.response_queue.pop(0)
                client.last_activity_ms = time.ticks_ms()
                
                # Close connection unless it's SSE
                if not client.is_sse_client:
                    self._cleanup_client(sock)
            
        except Exception as e:
            self._logger.error("Error sending response", client_ip=client.client_ip, error=str(e))
            self._cleanup_client(sock)
    
    def _send_error_response(self, client: ClientConnection, status_code: int, message: str) -> None:
        """Send error response to client."""
        response = HTTPResponse(status_code, message)
        response.set_json({"error": message, "code": status_code})
        client.response_queue.append(response)
    
    def _broadcast_sse_events(self) -> None:
        """Broadcast status updates to SSE clients."""
        sse_clients = [client for client in self._clients.values() if client.is_sse_client]
        if not sse_clients:
            return
        
        try:
            # Get current status
            status = self.controller.last_status
            if not status:
                return
            
            # Format as SSE event
            event_data = {
                "state": status.state,
                "temp_tenths": status.temp_tenths,
                "setpoint_tenths": status.setpoint_tenths,
                "cool_active": status.cool_active,
                "heat_active": status.heat_active,
                "alarm": status.alarm,
                "timestamp_ms": time.ticks_ms()
            }
            
            event_text = f"data: {json.dumps(event_data)}\n\n"
            event_bytes = event_text.encode('utf-8')
            
            # Send to all SSE clients
            dead_clients = []
            for client in sse_clients:
                try:
                    client.conn.send(event_bytes)
                    client.last_activity_ms = time.ticks_ms()
                except:
                    dead_clients.append(client.conn)
            
            # Clean up dead clients
            for sock in dead_clients:
                self._cleanup_client(sock)
                
        except Exception as e:
            self._logger.error("Error broadcasting SSE events", error=str(e))
    
    def _cleanup_client(self, sock: socket.socket) -> None:
        """Clean up client connection."""
        if sock in self._clients:
            client = self._clients[sock]
            client.close()
            del self._clients[sock]
            
            self._logger.debug("Client disconnected", 
                             client_ip=client.client_ip, 
                             total_clients=len(self._clients))
    
    def _cleanup_expired_clients(self) -> None:
        """Clean up expired client connections."""
        expired = []
        for sock, client in self._clients.items():
            if client.is_expired(self.CLIENT_TIMEOUT_MS):
                expired.append(sock)
        
        for sock in expired:
            self._cleanup_client(sock)
    
    def get_stats(self):
        """Get server statistics."""
        sse_clients = sum(1 for client in self._clients.values() if client.is_sse_client)
        
        return {
            "total_clients": len(self._clients),
            "sse_clients": sse_clients,
            "running": self._running,
            "max_clients": self.MAX_CLIENTS,
            "rate_limiter_stats": len(self._rate_limiter._requests)
        }
