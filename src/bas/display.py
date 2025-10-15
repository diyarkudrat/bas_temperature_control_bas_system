# display.py
# Production-grade OLED display with view model abstraction and status icons

import time
from machine import Pin, I2C
import bas.hardware.displays.ssd1306
from bas.services import Logger, LoggerFactory, SystemError, SystemErrorCodes

class DisplayViewModel:
    """View model for display abstraction - decouples display from controller format."""
    
    def __init__(self):
        # Current values
        self.temperature_c = None
        self.setpoint_c = 23.0
        self.deadband_c = 0.5
        self.cooling_active = False
        self.heating_active = False
        self.state = "IDLE"
        self.alarm = False
        self.sensor_ok = False
        self.error_code = 0
        
        # Display state
        self.last_update_ms = 0
        self.needs_refresh = True
        self.connection_status = "OFFLINE"  # OFFLINE, ONLINE, ERROR
        self.uptime_s = 0
        
        # Animation state
        self.blink_state = False
        self.last_blink_ms = 0
        
    def update_from_controller_status(self, status) -> bool:
        """Update view model from controller status. Returns True if display should refresh."""
        changed = False
        
        # Temperature
        new_temp = status.temp_tenths / 10.0 if status.temp_tenths is not None else None
        if new_temp != self.temperature_c:
            self.temperature_c = new_temp
            changed = True
        
        # Setpoints
        new_setpoint = status.setpoint_tenths / 10.0
        if new_setpoint != self.setpoint_c:
            self.setpoint_c = new_setpoint
            changed = True
        
        new_deadband = status.deadband_tenths / 10.0  
        if new_deadband != self.deadband_c:
            self.deadband_c = new_deadband
            changed = True
        
        # Actuator states
        if hasattr(status, 'cool_active'):
            if status.cool_active != self.cooling_active:
                self.cooling_active = status.cool_active
                changed = True
        elif hasattr(status, 'fan_on'):  # Legacy compatibility
            if status.fan_on != self.cooling_active:
                self.cooling_active = status.fan_on
                changed = True
        
        if hasattr(status, 'heat_active'):
            if status.heat_active != self.heating_active:
                self.heating_active = status.heat_active
                changed = True
        elif hasattr(status, 'heat_on'):  # Legacy compatibility
            if status.heat_on != self.heating_active:
                self.heating_active = status.heat_on
                changed = True
        
        # State and alarms
        if status.state != self.state:
            self.state = status.state
            changed = True
        
        if status.alarm != self.alarm:
            self.alarm = status.alarm
            changed = True
        
        if hasattr(status, 'sensor_ok'):
            if status.sensor_ok != self.sensor_ok:
                self.sensor_ok = status.sensor_ok
                changed = True
        else:
            # Infer sensor status from temperature availability
            sensor_ok = status.temp_tenths is not None
            if sensor_ok != self.sensor_ok:
                self.sensor_ok = sensor_ok
                changed = True
        
        if hasattr(status, 'error_code'):
            if status.error_code != self.error_code:
                self.error_code = status.error_code
                changed = True
        
        if changed:
            self.needs_refresh = True
            self.last_update_ms = time.ticks_ms()
        
        return changed
    
    def set_connection_status(self, status: str) -> None:
        """Update network connection status."""
        if status != self.connection_status:
            self.connection_status = status
            self.needs_refresh = True
    
    def set_uptime(self, uptime_s: int) -> None:
        """Update system uptime."""
        self.uptime_s = uptime_s
    
    def update_animation(self) -> bool:
        """Update animation state. Returns True if display should refresh."""
        current_ms = time.ticks_ms()
        
        # Blink every 500ms when in alarm state
        if self.alarm and time.ticks_diff(current_ms, self.last_blink_ms) >= 500:
            self.blink_state = not self.blink_state
            self.last_blink_ms = current_ms
            return True
        
        return False

class StatusIcons:
    """ASCII status icons for the OLED display."""
    
    # Connection status icons
    WIFI_CONNECTED = "W"
    WIFI_DISCONNECTED = "w"
    NETWORK_ERROR = "!"
    
    # Actuator status icons
    COOLING_ON = "C"
    COOLING_OFF = "c"
    HEATING_ON = "H"
    HEATING_OFF = "h"
    
    # System status icons
    ALARM = "!"
    SENSOR_OK = "S"
    SENSOR_FAULT = "s"
    
    # State icons
    STATE_IDLE = "-"
    STATE_COOLING = "C"
    STATE_HEATING = "H"
    STATE_FAULT = "X"

class Display:
    """Production-grade OLED display with throttling and status icons."""
    
    def __init__(self, sda_pin=0, scl_pin=1, update_throttle_ms=200):
        self.logger = LoggerFactory.get_logger("Display")
        self.sda_pin = sda_pin
        self.scl_pin = scl_pin
        self.update_throttle_ms = update_throttle_ms
        
        # Display state
        self.i2c = None
        self.oled = None
        self.is_initialized = False
        self.last_display_update_ms = 0
        self.initialization_attempts = 0
        self.max_init_attempts = 3
        
        # View model
        self.view_model = DisplayViewModel()
        
        # Initialize display
        self._initialize_display()
    
    def _initialize_display(self) -> bool:
        """Initialize the OLED display with error handling."""
        try:
            self.initialization_attempts += 1
            
            # Initialize I2C
            self.i2c = I2C(0, scl=Pin(self.scl_pin), sda=Pin(self.sda_pin), freq=400000)
            
            # Scan for devices
            devices = self.i2c.scan()
            if not devices:
                raise RuntimeError("No I2C devices found")
            
            # Initialize OLED (assuming SSD1306 at 0x3C)
            self.oled = ssd1306.SSD1306_I2C(128, 64, self.i2c)
            
            # Test display
            self.oled.fill(0)
            self.oled.text("BAS Controller", 0, 0)
            self.oled.text("Initializing...", 0, 12)
            self.oled.show()
            
            time.sleep_ms(1000)
            
            # Clear initialization screen
            self.oled.fill(0)
            self.oled.show()
            
            self.is_initialized = True
            self.logger.info("Display initialized successfully", 
                           sda_pin=self.sda_pin, scl_pin=self.scl_pin)
            return True
            
        except Exception as e:
            self.is_initialized = False
            
            if self.initialization_attempts <= self.max_init_attempts:
                self.logger.warning("Display initialization failed", 
                                  attempt=self.initialization_attempts,
                                  error=str(e))
            else:
                handle_error(
                    SystemErrorCodes.DISPLAY_INIT_FAILED,
                    f"Display initialization failed after {self.max_init_attempts} attempts: {e}",
                    "Display"
                )
            
            return False
    
    def update_status(self, status):
        """Update display with controller status (with throttling)."""
        # Update view model
        changed = self.view_model.update_from_controller_status(status)
        
        # Check animation updates
        animation_changed = self.view_model.update_animation()
        
        # Check if we should update display
        current_ms = time.ticks_ms()
        should_update = (
            changed or animation_changed or
            time.ticks_diff(current_ms, self.last_display_update_ms) >= self.update_throttle_ms
        )
        
        if should_update:
            self._render_display()
    
    def show_status(self, status):
        """Legacy method name for backward compatibility."""
        self.update_status(status)
    
    def set_connection_status(self, status: str) -> None:
        """Update network connection status."""
        self.view_model.set_connection_status(status)
        self._render_display()
    
    def set_uptime(self, uptime_s: int) -> None:
        """Update system uptime."""
        self.view_model.set_uptime(uptime_s)
    
    def _render_display(self) -> None:
        """Render the display based on current view model."""
        if not self.is_initialized:
            # Try to reinitialize
            if self.initialization_attempts < self.max_init_attempts:
                self._initialize_display()
            return
        
        try:
            self.oled.fill(0)
            
            # Render main content
            self._render_main_screen()
            
            # Show the display
            self.oled.show()
            
            self.last_display_update_ms = time.ticks_ms()
            self.view_model.needs_refresh = False
            
        except Exception as e:
            self.is_initialized = False
            if time.ticks_ms() % 10000 < 100:  # Log occasionally, not every time
                handle_error(
                    SystemErrorCodes.DISPLAY_I2C_ERROR,
                    f"Display rendering failed: {e}",
                    "Display"
                )
    
    def _render_main_screen(self) -> None:
        """Render the main status screen."""
        vm = self.view_model
        
        # Line 0: Title with status icons
        title_line = "BAS"
        
        # Add status icons
        if vm.connection_status == "ONLINE":
            title_line += f" {StatusIcons.WIFI_CONNECTED}"
        elif vm.connection_status == "ERROR":
            title_line += f" {StatusIcons.NETWORK_ERROR}"
        else:
            title_line += f" {StatusIcons.WIFI_DISCONNECTED}"
        
        if vm.sensor_ok:
            title_line += StatusIcons.SENSOR_OK
        else:
            title_line += StatusIcons.SENSOR_FAULT
        
        # State icon
        state_icon = {
            "IDLE": StatusIcons.STATE_IDLE,
            "COOLING": StatusIcons.STATE_COOLING,
            "HEATING": StatusIcons.STATE_HEATING,
            "FAULT": StatusIcons.STATE_FAULT
        }.get(vm.state, "?")
        title_line += state_icon
        
        self.oled.text(title_line, 0, 0)
        
        # Line 1: Temperature
        if vm.temperature_c is not None:
            temp_text = f"T: {vm.temperature_c:4.1f}C"
        else:
            temp_text = "T: ----C"
        self.oled.text(temp_text, 0, 12)
        
        # Line 2: Setpoint
        sp_text = f"SP:{vm.setpoint_c:4.1f}C"
        self.oled.text(sp_text, 0, 24)
        
        # Line 3: Actuator status
        cool_icon = StatusIcons.COOLING_ON if vm.cooling_active else StatusIcons.COOLING_OFF
        heat_icon = StatusIcons.HEATING_ON if vm.heating_active else StatusIcons.HEATING_OFF
        
        actuator_text = f"Fan:{cool_icon} Heat:{heat_icon}"
        self.oled.text(actuator_text, 0, 36)
        
        # Line 4: State and alarm
        state_text = f"State: {vm.state}"
        if len(state_text) > 16:
            state_text = state_text[:16]
        self.oled.text(state_text, 0, 48)
        
        # Line 5: Alarm (blinking if active)
        if vm.alarm:
            if vm.blink_state:
                alarm_text = "!! ALARM !!"
                self.oled.text(alarm_text, 0, 56)
                
                # Show error code if available
                if vm.error_code > 0:
                    error_text = f"Err:{vm.error_code}"
                    self.oled.text(error_text, 80, 56)
        else:
            # Show uptime when no alarm
            if vm.uptime_s > 0:
                uptime_text = self._format_uptime(vm.uptime_s)
                self.oled.text(uptime_text, 0, 56)
    
    def _format_uptime(self, uptime_s: int) -> str:
        """Format uptime as human-readable string."""
        if uptime_s < 60:
            return f"Up: {uptime_s}s"
        elif uptime_s < 3600:
            return f"Up: {uptime_s//60}m"
        elif uptime_s < 86400:
            hours = uptime_s // 3600
            minutes = (uptime_s % 3600) // 60
            return f"Up: {hours}h{minutes}m"
        else:
            days = uptime_s // 86400
            hours = (uptime_s % 86400) // 3600
            return f"Up: {days}d{hours}h"
    
    def show_boot_screen(self, message: str = "Booting...") -> None:
        """Show boot/startup screen."""
        if not self.is_initialized:
            return
        
        try:
            self.oled.fill(0)
            self.oled.text("BAS Controller", 16, 20)
            self.oled.text(message, 20, 32)
            self.oled.show()
        except:
            pass  # Ignore errors during boot
    
    def show_error_screen(self, error_message: str) -> None:
        """Show error screen."""
        if not self.is_initialized:
            return
        
        try:
            self.oled.fill(0)
            self.oled.text("SYSTEM ERROR", 16, 16)
            
            # Word wrap error message
            lines = self._word_wrap(error_message, 16)
            for i, line in enumerate(lines[:3]):  # Max 3 lines
                self.oled.text(line, 0, 32 + i * 12)
            
            self.oled.show()
        except:
            pass  # Ignore errors during error display
    
    def _word_wrap(self, text: str, width: int) -> list:
        """Simple word wrapping for display text."""
        words = text.split()
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line + " " + word) <= width:
                if current_line:
                    current_line += " " + word
                else:
                    current_line = word
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        
        if current_line:
            lines.append(current_line)
        
        return lines
    
    def clear(self) -> None:
        """Clear the display."""
        if self.is_initialized:
            try:
                self.oled.fill(0)
                self.oled.show()
            except:
                pass
    
    def close(self) -> None:
        """Clean up display resources."""
        if self.is_initialized:
            try:
                self.clear()
            except:
                pass
        
        self.is_initialized = False
        self.oled = None
        self.i2c = None
