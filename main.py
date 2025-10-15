# main.py
# Production-grade main loop with cooperative scheduling and proper error handling

import time
import gc
from core import DS18B20Sensor, Relay, SystemClock
from controller import CoolOnlyController
from display import Display
from netctrl.wifi import connect_wifi
from netctrl.api import HardenedApiServer
from services import ConfigManager, LoggerFactory, SystemError, SystemErrorCodes, handle_error, ErrorContext

class SystemOrchestrator:
    """Orchestrates all system components with cooperative scheduling."""
    
    def __init__(self):
        self.logger = LoggerFactory.get_logger("SystemOrchestrator")
        self.config_manager = ConfigManager()
        self.controller = None
        self.display = None
        self.api_server = None
        self.clock = SystemClock()
        
        # System state
        self.running = False
        self.last_gc_ms = 0
        self.last_status_ms = 0
        self.boot_time_ms = time.ticks_ms()
        
        # Performance monitoring
        self.cycle_count = 0
        self.last_cycle_time_ms = 0
    
    def initialize(self) :
        """Initialize all system components."""
        self.logger.info("Starting system initialization")
        
        try:
            # Load configuration
            if not self._init_config():
                return False
            
            # Initialize hardware  
            if not self._init_hardware():
                return False
            
            # Initialize networking
            if not self._init_networking():
                return False
            
            # Initialize controller
            if not self._init_controller():
                return False
            
            # Initialize display
            if not self._init_display():
                return False
            
            # Initialize API server
            if not self._init_api_server():
                return False
            
            self.logger.info("System initialization completed successfully")
            return True
            
        except Exception as e:
            handle_error(
                SystemErrorCodes.SYSTEM_BOOT_FAILED,
                f"System initialization failed: {e}",
                "SystemOrchestrator"
            )
            return False
    
    def _init_config(self):
        """Initialize configuration management."""
        try:
            # Try to load from flash, fall back to defaults
            loaded = self.config_manager.load_from_flash()
            if not loaded:
                self.logger.warning("Using default configuration - flash config not found")
            
            # Load secrets separately, fall back to config.py
            secrets = self.config_manager.load_secrets()
            profile = self.config_manager.get_current_profile()
            
            # Apply secrets to profile, with fallback to config.py
            if secrets:
                profile.wifi_ssid = secrets.get('wifi_ssid')
                profile.wifi_password = secrets.get('wifi_password')
                profile.api_token = secrets.get('api_token')
            
            # Fallback to config.py if no secrets file
            if not profile.wifi_ssid or not profile.wifi_password:
                try:
                    from config.config import WIFI_SSID, WIFI_PASS, API_TOKEN
                    profile.wifi_ssid = WIFI_SSID
                    profile.wifi_password = WIFI_PASS
                    profile.api_token = API_TOKEN
                    self.logger.info("Using WiFi credentials from config.py")
                except ImportError:
                    self.logger.warning("No WiFi credentials available")
            
            # Set logging level based on config
            if profile.enable_debug_logs:
                LoggerFactory.set_global_level(20)  # INFO
            else:
                LoggerFactory.set_global_level(30)  # WARNING
            
            self.logger.info("Configuration initialized", profile=profile.profile_name)
            return True
            
        except Exception as e:
            self.logger.error("Configuration initialization failed", error=str(e))
            return False
    
    def _init_hardware(self) :
        """Initialize hardware components."""
        try:
            profile = self.config_manager.get_current_profile()
            
            # Initialize sensor
            with ErrorContext("Hardware", "sensor_init"):
                self.sensor = DS18B20Sensor(profile.pin_ds18b20)
            
            # Initialize actuators
            with ErrorContext("Hardware", "actuator_init"):
                self.cool_relay = Relay(profile.pin_relay_cool, "COOL")
                self.heat_relay = Relay(profile.pin_relay_heat, "HEAT")
            
            self.logger.info("Hardware initialized successfully")
            return True
            
        except Exception as e:
            handle_error(
                SystemErrorCodes.ACTUATOR_INIT_FAILED,
                f"Hardware initialization failed: {e}",
                "Hardware"
            )
            return False
    
    def _init_networking(self) :
        """Initialize network connection."""
        try:
            profile = self.config_manager.get_current_profile()
            
            if not profile.wifi_ssid or not profile.wifi_password:
                self.logger.warning("No WiFi credentials - networking disabled")
                return True  # Not critical
            
            with ErrorContext("Networking", "wifi_connect"):
                ip = connect_wifi(profile.wifi_ssid, profile.wifi_password, timeout_s=30)
                self.logger.info("WiFi connected", ip=ip)
            
            return True
            
        except Exception as e:
            # Network failure is not critical - system can run offline
            self.logger.warning("Network initialization failed", error=str(e))
            return True
    
    def _init_controller(self) :
        """Initialize temperature controller.""" 
        try:
            profile = self.config_manager.get_current_profile()
            
            self.controller = CoolOnlyController(
                sensor=self.sensor,
                cool_actuator=self.cool_relay,
                heat_actuator=self.heat_relay,
                clock=self.clock,
                setpoint_tenths=profile.setpoint_tenths,
                deadband_tenths=profile.deadband_tenths,
                min_on_ms=profile.min_on_ms,
                min_off_ms=profile.min_off_ms,
                max_sensor_age_ms=profile.max_sensor_age_ms,
                heat_always_on=profile.heat_always_on
            )
            
            self.logger.info("Controller initialized", 
                           setpoint_c=profile.setpoint_tenths/10.0,
                           deadband_c=profile.deadband_tenths/10.0)
            return True
            
        except Exception as e:
            handle_error(
                SystemErrorCodes.CONTROLLER_CONFIG_ERROR,
                f"Controller initialization failed: {e}",
                "Controller"
            )
            return False
    
    def _init_display(self) :
        """Initialize display."""
        try:
            with ErrorContext("Display", "display_init"):
                self.display = Display()
            
            self.logger.info("Display initialized successfully")
            return True
            
        except Exception as e:
            # Display failure is not critical
            handle_error(
                SystemErrorCodes.DISPLAY_INIT_FAILED,
                f"Display initialization failed: {e}",
                "Display",
                attempt_recovery=False
            )
            self.display = None
            return True
    
    def _init_api_server(self) :
        """Initialize API server."""
        try:
            profile = self.config_manager.get_current_profile()
            
            if not profile.api_token:
                self.logger.warning("No API token - web interface disabled")
                return True
            
            # Initialize server with multiple token support
            tokens = [profile.api_token]
            self.api_server = HardenedApiServer(
                controller=self.controller,
                config_manager=self.config_manager,
                auth_tokens=tokens
            )
            
            # Start server
            if self.api_server.start(port=80):
                self.logger.info("API server started successfully")
                return True
            else:
                self.api_server = None
                self.logger.warning("API server failed to start - web interface disabled")
                return True  # Not critical
                
        except Exception as e:
            # API server failure is not critical
            self.logger.warning("API server initialization failed", error=str(e))
            self.api_server = None
            return True
    
    def run(self) :
        """Main system loop with cooperative scheduling."""
        if not self.initialize():
            self.logger.critical("System initialization failed - cannot start")
            return
        
        self.running = True
        profile = self.config_manager.get_current_profile()
        sample_period_ms = profile.sample_period_ms
        
        self.logger.info("Starting main system loop", sample_period_ms=sample_period_ms)
        
        try:
            while self.running:
                cycle_start = time.ticks_ms()
                
                # Controller step (highest priority)
                self._controller_step()
                
                # Display update
                self._display_step()
                
                # Network processing (non-blocking)
                self._network_step()
                
                # Housekeeping
                self._housekeeping_step()
                
                # Calculate cycle time and sleep
                cycle_time = time.ticks_diff(time.ticks_ms(), cycle_start)
                self.last_cycle_time_ms = cycle_time
                self.cycle_count += 1
                
                # Sleep for remainder of sample period
                remaining_ms = max(0, sample_period_ms - cycle_time)
                if remaining_ms > 0:
                    time.sleep_ms(remaining_ms)
                else:
                    # Cycle overrun warning
                    if self.cycle_count % 100 == 0:  # Don't flood logs
                        self.logger.warning("Cycle time overrun", 
                                          cycle_time_ms=cycle_time, 
                                          target_ms=sample_period_ms)
                
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
        except Exception as e:
            handle_error(
                SystemErrorCodes.SYSTEM_UNKNOWN_ERROR,
                f"Fatal error in main loop: {e}",
                "SystemOrchestrator"
            )
        finally:
            self.shutdown()
    
    def _controller_step(self) :
        """Execute controller step with error handling."""
        try:
            if self.controller:
                status = self.controller.step()
                
                # Check if debug logs are enabled
                try:
                    from config.config import ENABLE_DEBUG_LOGS
                    debug_enabled = ENABLE_DEBUG_LOGS
                except:
                    debug_enabled = False
                
                # Log status every cycle if debug enabled (like V1)
                if debug_enabled:
                    temp_str = f"{status.temp_tenths/10.0:.1f}" if status.temp_tenths else "---"
                    print(f"T={temp_str}°C SP={status.setpoint_tenths/10.0:.1f}°C State={status.state} Cool={'ON' if status.cool_active else 'OFF'} Heat={'ON' if status.heat_active else 'OFF'}")
                
                # Always log alarms
                if status.alarm:
                    self.logger.warning("Controller alarm", 
                                      error_code=status.error_code,
                                      state=status.state)
                
                # Log periodic summary for monitoring
                current_time = time.ticks_ms()
                if time.ticks_diff(current_time, self.last_status_ms) > 60000:  # Every minute
                    self.logger.info("Controller status",
                                   state=status.state,
                                   temp_c=status.temp_tenths/10.0 if status.temp_tenths else None,
                                   setpoint_c=status.setpoint_tenths/10.0,
                                   cool_active=status.cool_active)
                    self.last_status_ms = current_time
                    
        except Exception as e:
            handle_error(
                SystemErrorCodes.CONTROLLER_INVALID_STATE,
                f"Controller step failed: {e}",
                "Controller"
            )
    
    def _display_step(self) :
        """Update display with throttling."""
        try:
            if self.display and self.controller and self.controller.last_status:
                # Convert new status format to legacy format for display
                status = self.controller.last_status
                
                # Display already uses view model pattern, just pass status directly
                self.display.update_status(status)
                
        except Exception as e:
            # Display errors are not critical
            if self.cycle_count % 100 == 0:  # Don't flood logs
                self.logger.warning("Display update failed", error=str(e))
    
    def _network_step(self) :
        """Process network events (non-blocking)."""
        try:
            if self.api_server:
                # Process network events with short timeout
                self.api_server.process_events(timeout_ms=10)
                
        except Exception as e:
            if self.cycle_count % 100 == 0:  # Don't flood logs
                self.logger.warning("Network processing failed", error=str(e))
    
    def _housekeeping_step(self) :
        """Perform housekeeping tasks."""
        current_time = time.ticks_ms()
        
        # Periodic garbage collection
        if time.ticks_diff(current_time, self.last_gc_ms) > 10000:  # Every 10 seconds
            try:
                gc.collect()
                self.last_gc_ms = current_time
                
                # Log memory stats occasionally  
                if self.cycle_count % 300 == 0:  # Every 5 minutes at 1Hz
                    mem_free = gc.mem_free()
                    mem_alloc = gc.mem_alloc()
                    self.logger.debug("Memory stats", 
                                    free_bytes=mem_free, 
                                    allocated_bytes=mem_alloc,
                                    uptime_s=(current_time - self.boot_time_ms) // 1000)
                    
            except Exception as e:
                self.logger.warning("Garbage collection failed", error=str(e))
    
    def shutdown(self) :
        """Graceful system shutdown."""
        self.logger.info("Starting system shutdown")
        self.running = False
        
        try:
            # Stop API server
            if self.api_server:
                self.api_server.stop()
                self.api_server = None
            
            # Put controller in safe state
            if self.controller:
                self.controller.force_safe_state()
            
            # Clear display
            if self.display:
                self.display.clear()
            
            # Save configuration
            try:
                self.config_manager.save_to_flash()
            except:
                pass  # Non-critical
            
            self.logger.info("System shutdown completed")
            
        except Exception as e:
            self.logger.error("Error during shutdown", error=str(e))

def main():
    """Main entry point."""
    orchestrator = SystemOrchestrator()
    orchestrator.run()

if __name__ == "__main__":
    main()
