# services/config_manager_compat.py
# MicroPython-compatible configuration management (without typing/dataclasses)

try:
    import ujson as json
except ImportError:
    import json

class ConfigError(Exception):
    """Configuration-related errors."""
    pass

class ConfigProfile:
    """Configuration profile with validation."""
    
    def __init__(self, profile_name="default"):
        self.profile_name = profile_name
        
        # Control parameters (runtime tunable)
        self.setpoint_tenths = 230  # 23.0°C
        self.deadband_tenths = 5    # 0.5°C
        self.sample_period_ms = 2000
        self.min_on_ms = 10000
        self.min_off_ms = 10000
        self.max_sensor_age_ms = 8000
        
        # Hardware config (boot-time only)
        self.pin_relay_heat = 14
        self.pin_relay_cool = 15
        self.pin_ds18b20 = 4
        self.i2c_sda = 0
        self.i2c_scl = 1
        
        # Behavior flags
        self.cool_only = True
        self.heat_always_on = True
        self.relay_active_high = True
        self.enable_debug_logs = False
        
        # Network (sensitive - loaded separately)
        self.wifi_ssid = None
        self.wifi_password = None
        self.api_token = None
    
    def validate(self):
        """Validate configuration parameters."""
        errors = []
        
        if not (-400 <= self.setpoint_tenths <= 800):
            errors.append(f"Invalid setpoint: {self.setpoint_tenths/10}C")
        
        if not (1 <= self.deadband_tenths <= 100):
            errors.append(f"Invalid deadband: {self.deadband_tenths/10}C")
        
        if not (100 <= self.sample_period_ms <= 60000):
            errors.append(f"Invalid sample period: {self.sample_period_ms}ms")
        
        if errors:
            raise ConfigError(f"Config validation failed: {'; '.join(errors)}")
    
    def to_dict(self):
        """Convert to dictionary for serialization."""
        return {
            'profile_name': self.profile_name,
            'setpoint_tenths': self.setpoint_tenths,
            'deadband_tenths': self.deadband_tenths,
            'sample_period_ms': self.sample_period_ms,
            'min_on_ms': self.min_on_ms,
            'min_off_ms': self.min_off_ms,
            'cool_only': self.cool_only,
            'heat_always_on': self.heat_always_on,
            'enable_debug_logs': self.enable_debug_logs
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create profile from dictionary."""
        profile = cls(data.get('profile_name', 'default'))
        
        for key, value in data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        
        profile.validate()
        return profile

class ConfigManager:
    """Manages configuration profiles."""
    
    CONFIG_FILE = '/config.json'
    SECRETS_FILE = '/secrets.json'
    
    def __init__(self):
        self._current_profile = None
        self._profiles = {}
        self._init_default_profiles()
    
    def _init_default_profiles(self):
        """Initialize built-in profiles."""
        default = ConfigProfile("default")
        default.setpoint_tenths = 230
        self._profiles["default"] = default
    
    def load_from_flash(self):
        """Load configuration from flash storage."""
        try:
            with open(self.CONFIG_FILE, 'r') as f:
                data = json.load(f)
            
            for profile_data in data.get('profiles', []):
                profile = ConfigProfile.from_dict(profile_data)
                self._profiles[profile.profile_name] = profile
            
            current_name = data.get('current_profile', 'default')
            if current_name in self._profiles:
                self._current_profile = self._profiles[current_name]
            
            return True
        except Exception as e:
            print(f"Failed to load config: {e}")
            self._current_profile = self._profiles["default"]
            return False
    
    def get_current_profile(self):
        """Get current active profile."""
        if self._current_profile is None:
            self._current_profile = self._profiles["default"]
        return self._current_profile
    
    def update_runtime_config(self, **kwargs):
        """Update runtime-tunable parameters."""
        if self._current_profile is None:
            return False
        
        try:
            runtime_params = {
                'setpoint_tenths', 'deadband_tenths', 'sample_period_ms',
                'min_on_ms', 'min_off_ms', 'enable_debug_logs'
            }
            
            for key, value in kwargs.items():
                if key in runtime_params and hasattr(self._current_profile, key):
                    setattr(self._current_profile, key, value)
            
            self._current_profile.validate()
            return True
        except Exception as e:
            print(f"Config update failed: {e}")
            return False

# Simple exports for compatibility
ConfigManager = ConfigManager
ConfigProfile = ConfigProfile
