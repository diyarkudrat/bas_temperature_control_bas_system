# services/config_manager.py
# Configuration management with profiles, validation, and persistence

import ujson as json
from micropython import const
# typing removed for MicroPython

class ConfigError(Exception):
    """Configuration-related errors."""
    pass

class ConfigProfile:
    """Configuration profile with validation."""
    
    # System behavior defaults
    DEFAULT_SETPOINT_TENTHS = const(230)  # 23.0°C  
    DEFAULT_DEADBAND_TENTHS = const(5)    # 0.5°C
    DEFAULT_SAMPLE_PERIOD_MS = const(2000)
    DEFAULT_MIN_ON_MS = const(10000)
    DEFAULT_MIN_OFF_MS = const(10000)
    DEFAULT_MAX_SENSOR_AGE_MS = const(8000)
    
    # Hardware defaults
    DEFAULT_PIN_RELAY_HEAT = const(14)
    DEFAULT_PIN_RELAY_COOL = const(15)
    DEFAULT_PIN_DS18B20 = const(4)
    DEFAULT_I2C_SDA = const(0)
    DEFAULT_I2C_SCL = const(1)
    
    def __init__(self, profile_name: str = "default"):
        self.profile_name = profile_name
        
        # Control parameters (runtime tunable)
        self.setpoint_tenths = self.DEFAULT_SETPOINT_TENTHS
        self.deadband_tenths = self.DEFAULT_DEADBAND_TENTHS
        self.sample_period_ms = self.DEFAULT_SAMPLE_PERIOD_MS
        self.min_on_ms = self.DEFAULT_MIN_ON_MS
        self.min_off_ms = self.DEFAULT_MIN_OFF_MS
        self.max_sensor_age_ms = self.DEFAULT_MAX_SENSOR_AGE_MS
        
        # Hardware config (boot-time only)
        self.pin_relay_heat = self.DEFAULT_PIN_RELAY_HEAT
        self.pin_relay_cool = self.DEFAULT_PIN_RELAY_COOL
        self.pin_ds18b20 = self.DEFAULT_PIN_DS18B20
        self.i2c_sda = self.DEFAULT_I2C_SDA
        self.i2c_scl = self.DEFAULT_I2C_SCL
        
        # Behavior flags
        self.cool_only = True
        self.heat_always_on = True
        self.relay_active_high = True
        self.enable_debug_logs = False
        
        # Network (sensitive - loaded separately)
        self.wifi_ssid = None
        self.wifi_password = None
        self.api_token = None
    
    def validate(self) :
        """Validate configuration parameters."""
        errors = []
        
        # Temperature validation
        if not (-400 <= self.setpoint_tenths <= 800):  # -40°C to +80°C
            errors.append(f"Invalid setpoint: {self.setpoint_tenths/10}°C (range: -40 to +80°C)")
        
        if not (1 <= self.deadband_tenths <= 100):  # 0.1°C to 10°C
            errors.append(f"Invalid deadband: {self.deadband_tenths/10}°C (range: 0.1 to 10°C)")
        
        # Timing validation
        if not (100 <= self.sample_period_ms <= 60000):  # 0.1s to 60s
            errors.append(f"Invalid sample period: {self.sample_period_ms}ms (range: 100-60000ms)")
            
        if not (1000 <= self.min_on_ms <= 300000):  # 1s to 5min
            errors.append(f"Invalid min_on_ms: {self.min_on_ms}ms (range: 1000-300000ms)")
            
        if not (1000 <= self.min_off_ms <= 300000):  # 1s to 5min  
            errors.append(f"Invalid min_off_ms: {self.min_off_ms}ms (range: 1000-300000ms)")
        
        # GPIO validation (Pico W has GPIO 0-28)
        gpio_pins = [self.pin_relay_heat, self.pin_relay_cool, self.pin_ds18b20, self.i2c_sda, self.i2c_scl]
        for pin in gpio_pins:
            if not (0 <= pin <= 28):
                errors.append(f"Invalid GPIO pin: {pin} (range: 0-28)")
        
        # Check for pin conflicts
        if len(set(gpio_pins)) != len(gpio_pins):
            errors.append("GPIO pin conflict detected")
        
        if errors:
            raise ConfigError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def to_dict(self) :
        """Convert to dictionary for serialization (excludes sensitive data)."""
        return {
            'profile_name': self.profile_name,
            'setpoint_tenths': self.setpoint_tenths,
            'deadband_tenths': self.deadband_tenths,
            'sample_period_ms': self.sample_period_ms,
            'min_on_ms': self.min_on_ms,
            'min_off_ms': self.min_off_ms,
            'max_sensor_age_ms': self.max_sensor_age_ms,
            'pin_relay_heat': self.pin_relay_heat,
            'pin_relay_cool': self.pin_relay_cool,
            'pin_ds18b20': self.pin_ds18b20,
            'i2c_sda': self.i2c_sda,
            'i2c_scl': self.i2c_scl,
            'cool_only': self.cool_only,
            'heat_always_on': self.heat_always_on,
            'relay_active_high': self.relay_active_high,
            'enable_debug_logs': self.enable_debug_logs
        }
    
    @classmethod
    def from_dict(cls, data) -> 'ConfigProfile':
        """Create profile from dictionary."""
        profile = cls(data.get('profile_name', 'default'))
        
        # Update with provided values
        for key, value in data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        
        profile.validate()
        return profile

class ConfigManager:
    """Manages configuration profiles with persistence and runtime updates."""
    
    CONFIG_FILE = '/config.json'
    SECRETS_FILE = '/secrets.json'  # WiFi credentials, API tokens
    
    def __init__(self):
        self._current_profile = None
        self._profiles = {}
        
        # Load default profiles
        self._init_default_profiles()
    
    def _init_default_profiles(self) :
        """Initialize built-in profiles."""
        # Default production profile
        default = ConfigProfile("default")
        default.setpoint_tenths = 230  # 23.0°C
        default.enable_debug_logs = False
        self._profiles["default"] = default
        
        # Development profile with more logging
        dev = ConfigProfile("development") 
        dev.setpoint_tenths = 200  # 20.0°C (cooler for testing)
        dev.enable_debug_logs = True
        dev.sample_period_ms = 1000  # Faster updates
        self._profiles["development"] = dev
        
        # High-temp profile
        hot = ConfigProfile("high_temp")
        hot.setpoint_tenths = 280  # 28.0°C
        hot.deadband_tenths = 10   # 1.0°C (wider deadband)
        self._profiles["high_temp"] = hot
    
    def load_from_flash(self) :
        """Load configuration from flash storage."""
        try:
            # Load main config
            with open(self.CONFIG_FILE, 'r') as f:
                data = json.load(f)
            
            # Load profiles
            for profile_data in data.get('profiles', []):
                profile = ConfigProfile.from_dict(profile_data)
                self._profiles[profile.profile_name] = profile
            
            # Set current profile
            current_name = data.get('current_profile', 'default')
            if current_name in self._profiles:
                self._current_profile = self._profiles[current_name]
                
            return True
            
        except Exception as e:
            print(f"Failed to load config from flash: {e}")
            # Fall back to default profile
            self._current_profile = self._profiles["default"]
            return False
    
    def save_to_flash(self) :
        """Save configuration to flash storage."""
        try:
            data = {
                'current_profile': self._current_profile.profile_name if self._current_profile else 'default',
                'profiles': [profile.to_dict() for profile in self._profiles.values()]
            }
            
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(data, f)
            
            return True
            
        except Exception as e:
            print(f"Failed to save config to flash: {e}")
            return False
    
    def load_secrets(self) :
        """Load secrets from separate file."""
        try:
            with open(self.SECRETS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            # Return empty dict if file doesn't exist
            return {}
    
    def save_secrets(self, secrets) :
        """Save secrets to separate file."""
        try:
            with open(self.SECRETS_FILE, 'w') as f:
                json.dump(secrets, f)
            return True
        except Exception as e:
            print(f"Failed to save secrets: {e}")
            return False
    
    def get_current_profile(self) -> ConfigProfile:
        """Get current active profile."""
        if self._current_profile is None:
            self._current_profile = self._profiles["default"]
        return self._current_profile
    
    def set_profile(self, profile_name: str) :
        """Switch to specified profile."""
        if profile_name not in self._profiles:
            return False
        
        self._current_profile = self._profiles[profile_name]
        return True
    
    def update_runtime_config(self, **kwargs) :
        """Update runtime-tunable parameters."""
        if self._current_profile is None:
            return False
        
        try:
            # Only allow runtime-safe parameters
            runtime_params = {
                'setpoint_tenths', 'deadband_tenths', 'sample_period_ms',
                'min_on_ms', 'min_off_ms', 'max_sensor_age_ms', 'enable_debug_logs'
            }
            
            for key, value in kwargs.items():
                if key in runtime_params and hasattr(self._current_profile, key):
                    setattr(self._current_profile, key, value)
            
            # Validate after updates
            self._current_profile.validate()
            return True
            
        except Exception as e:
            print(f"Config update failed: {e}")
            return False
    
    def list_profiles(self) -> list:
        """List available profile names."""
        return list(self._profiles.keys())
    
    def get_profile_summary(self) :
        """Get summary of current profile for API."""
        profile = self.get_current_profile()
        return {
            'profile_name': profile.profile_name,
            'setpoint_c': profile.setpoint_tenths / 10.0,
            'deadband_c': profile.deadband_tenths / 10.0,
            'sample_period_s': profile.sample_period_ms / 1000.0,
            'available_profiles': self.list_profiles()
        }
