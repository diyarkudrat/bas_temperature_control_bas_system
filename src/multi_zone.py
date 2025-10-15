# blueprints/multi_zone.py
# Multi-zone architecture blueprint implementation

# typing removed for MicroPython
from dataclasses import dataclass, field
from interfaces import TemperatureSensor, Actuator, Clock
from controller_v2 import CoolOnlyController, ControllerStatus
from services import Logger, LoggerFactory, SystemError, SystemErrorCodes
import time

@dataclass
class ZoneConfig:
    """Configuration for a single zone."""
    zone_id: str
    name: str
    enabled: bool = True
    sensor_address: str = ""
    cooling_pin: int = -1
    heating_pin: int = -1
    setpoint_tenths: int = 230
    deadband_tenths: int = 10
    min_on_ms: int = 10000
    min_off_ms: int = 10000
    priority: int = 1  # 1=highest, higher numbers = lower priority

@dataclass
class ZoneStatus:
    """Status of a single zone."""
    zone_id: str
    name: str
    enabled: bool
    controller_status: ControllerStatus
    last_update_ms: int
    error_count: int = 0

class SystemEvent:
    """System event for pub/sub messaging."""
    
    def __init__(self, event_type: str, source: str, data: Dict[str, Any] = None):
        self.event_type = event_type
        self.source = source
        self.timestamp_ms = time.ticks_ms()
        self.data = data or {}
        self.event_id = f"{source}_{event_type}_{self.timestamp_ms}"

class EventBus:
    """Simple event bus for system coordination."""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._logger = LoggerFactory.get_logger("EventBus")
        self._event_count = 0
    
    def subscribe(self, event_type: str, handler: Callable[[SystemEvent], None]) -> None:
        """Subscribe to event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
        self._logger.debug("Subscribed to event", event_type=event_type, 
                          total_subscribers=len(self._subscribers[event_type]))
    
    def publish(self, event: SystemEvent) -> None:
        """Publish event to all subscribers."""
        self._event_count += 1
        
        if event.event_type in self._subscribers:
            for handler in self._subscribers[event.event_type]:
                try:
                    handler(event)
                except Exception as e:
                    self._logger.error("Event handler failed", 
                                     event_type=event.event_type,
                                     error=str(e))
        
        # Log high-frequency events less often
        if self._event_count % 100 == 0:
            self._logger.debug("Event bus stats", total_events=self._event_count,
                             event_types=len(self._subscribers))

class ZoneScheduler:
    """Cooperative scheduler for multiple zones."""
    
    def __init__(self, clock: Clock, max_cycle_time_ms: int = 50):
        self.clock = clock
        self.max_cycle_time_ms = max_cycle_time_ms
        self._zones: List[str] = []
        self._current_index = 0
        self._cycle_stats = {
            'total_cycles': 0,
            'overrun_cycles': 0,
            'avg_cycle_time_ms': 0
        }
        self._logger = LoggerFactory.get_logger("ZoneScheduler")
    
    def register_zone(self, zone_id: str) -> None:
        """Register zone for scheduling."""
        if zone_id not in self._zones:
            self._zones.append(zone_id)
            self._logger.info("Zone registered", zone_id=zone_id, total_zones=len(self._zones))
    
    def get_next_zone(self) -> Optional[str]:
        """Get next zone to process (round-robin)."""
        if not self._zones:
            return None
        
        zone_id = self._zones[self._current_index]
        self._current_index = (self._current_index + 1) % len(self._zones)
        return zone_id
    
    def record_cycle_time(self, cycle_time_ms: int) -> None:
        """Record cycle timing statistics."""
        self._cycle_stats['total_cycles'] += 1
        
        if cycle_time_ms > self.max_cycle_time_ms:
            self._cycle_stats['overrun_cycles'] += 1
        
        # Update running average
        total = self._cycle_stats['total_cycles']
        current_avg = self._cycle_stats['avg_cycle_time_ms']
        self._cycle_stats['avg_cycle_time_ms'] = (current_avg * (total - 1) + cycle_time_ms) / total
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        stats = self._cycle_stats.copy()
        stats['total_zones'] = len(self._zones)
        stats['overrun_rate'] = (
            self._cycle_stats['overrun_cycles'] / max(1, self._cycle_stats['total_cycles']) * 100
        )
        return stats

class MultiZoneManager:
    """Manages multiple temperature control zones."""
    
    def __init__(self, clock: Clock, event_bus: EventBus):
        self.clock = clock
        self.event_bus = event_bus
        self._logger = LoggerFactory.get_logger("MultiZoneManager")
        
        # Zone management
        self._zones: Dict[str, ZoneConfig] = {}
        self._controllers: Dict[str, CoolOnlyController] = {}
        self._zone_statuses: Dict[str, ZoneStatus] = {}
        
        # Scheduling
        self._scheduler = ZoneScheduler(clock)
        self._last_stats_ms = 0
        
        # Subscribe to system events
        self.event_bus.subscribe("zone.config.update", self._handle_zone_config_update)
        self.event_bus.subscribe("system.shutdown", self._handle_system_shutdown)
    
    def add_zone(self, config: ZoneConfig, sensor: TemperatureSensor, 
                 cool_actuator: Actuator, heat_actuator: Actuator) -> bool:
        """Add a new zone to the system."""
        try:
            if config.zone_id in self._zones:
                self._logger.warning("Zone already exists", zone_id=config.zone_id)
                return False
            
            # Create controller for zone
            controller = CoolOnlyController(
                sensor=sensor,
                cool_actuator=cool_actuator,
                heat_actuator=heat_actuator,
                clock=self.clock,
                setpoint_tenths=config.setpoint_tenths,
                deadband_tenths=config.deadband_tenths,
                min_on_ms=config.min_on_ms,
                min_off_ms=config.min_off_ms,
                heat_always_on=True  # Default for now
            )
            
            # Store zone configuration and controller
            self._zones[config.zone_id] = config
            self._controllers[config.zone_id] = controller
            
            # Initialize zone status
            self._zone_statuses[config.zone_id] = ZoneStatus(
                zone_id=config.zone_id,
                name=config.name,
                enabled=config.enabled,
                controller_status=controller.step(),  # Initial status
                last_update_ms=self.clock.now_ms()
            )
            
            # Register with scheduler
            if config.enabled:
                self._scheduler.register_zone(config.zone_id)
            
            # Publish event
            self.event_bus.publish(SystemEvent(
                "zone.added",
                "MultiZoneManager",
                {"zone_id": config.zone_id, "name": config.name}
            ))
            
            self._logger.info("Zone added successfully", 
                            zone_id=config.zone_id, 
                            name=config.name,
                            total_zones=len(self._zones))
            return True
            
        except Exception as e:
            self._logger.error("Failed to add zone", zone_id=config.zone_id, error=str(e))
            return False
    
    def remove_zone(self, zone_id: str) -> bool:
        """Remove zone from system."""
        try:
            if zone_id not in self._zones:
                return False
            
            # Clean up controller
            if zone_id in self._controllers:
                self._controllers[zone_id].force_safe_state()
                self._controllers[zone_id].close()
                del self._controllers[zone_id]
            
            # Clean up zone data
            del self._zones[zone_id]
            if zone_id in self._zone_statuses:
                del self._zone_statuses[zone_id]
            
            # Publish event
            self.event_bus.publish(SystemEvent(
                "zone.removed",
                "MultiZoneManager",
                {"zone_id": zone_id}
            ))
            
            self._logger.info("Zone removed", zone_id=zone_id)
            return True
            
        except Exception as e:
            self._logger.error("Failed to remove zone", zone_id=zone_id, error=str(e))
            return False
    
    def step(self) -> None:
        """Execute one step of multi-zone control."""
        cycle_start = self.clock.now_ms()
        
        try:
            # Get next zone to process
            zone_id = self._scheduler.get_next_zone()
            if not zone_id:
                return
            
            # Skip disabled zones
            config = self._zones.get(zone_id)
            if not config or not config.enabled:
                return
            
            # Execute controller step
            controller = self._controllers.get(zone_id)
            if controller:
                status = controller.step()
                
                # Update zone status
                zone_status = self._zone_statuses[zone_id]
                zone_status.controller_status = status
                zone_status.last_update_ms = self.clock.now_ms()
                
                # Check for alarms
                if status.alarm:
                    zone_status.error_count += 1
                    self.event_bus.publish(SystemEvent(
                        "zone.alarm",
                        zone_id,
                        {
                            "error_code": status.error_code,
                            "state": status.state,
                            "error_count": zone_status.error_count
                        }
                    ))
                
                # Publish state changes
                if hasattr(self, '_last_states') and zone_id in self._last_states:
                    if self._last_states[zone_id] != status.state:
                        self.event_bus.publish(SystemEvent(
                            "zone.state.change",
                            zone_id,
                            {"old_state": self._last_states[zone_id], "new_state": status.state}
                        ))
                
                # Track state for change detection
                if not hasattr(self, '_last_states'):
                    self._last_states = {}
                self._last_states[zone_id] = status.state
            
            # Record cycle time
            cycle_time = self.clock.elapsed_ms(cycle_start)
            self._scheduler.record_cycle_time(cycle_time)
            
            # Periodic statistics logging
            current_time = self.clock.now_ms()
            if self.clock.elapsed_ms(self._last_stats_ms) > 60000:  # Every minute
                self._log_system_stats()
                self._last_stats_ms = current_time
                
        except Exception as e:
            self._logger.error("Error in multi-zone step", error=str(e))
    
    def get_zone_status(self, zone_id: str) -> Optional[ZoneStatus]:
        """Get status for specific zone."""
        return self._zone_statuses.get(zone_id)
    
    def get_all_zone_statuses(self) -> Dict[str, ZoneStatus]:
        """Get status for all zones."""
        return self._zone_statuses.copy()
    
    def update_zone_config(self, zone_id: str, updates: Dict[str, Any]) -> bool:
        """Update zone configuration at runtime."""
        try:
            if zone_id not in self._zones:
                return False
            
            config = self._zones[zone_id]
            controller = self._controllers.get(zone_id)
            
            # Apply updates
            if 'setpoint_tenths' in updates and controller:
                controller.set_setpoint_tenths(updates['setpoint_tenths'])
                config.setpoint_tenths = updates['setpoint_tenths']
            
            if 'deadband_tenths' in updates and controller:
                controller.set_deadband_tenths(updates['deadband_tenths'])
                config.deadband_tenths = updates['deadband_tenths']
            
            if 'enabled' in updates:
                config.enabled = updates['enabled']
                # Update scheduler registration
                if config.enabled:
                    self._scheduler.register_zone(zone_id)
            
            # Publish config update event
            self.event_bus.publish(SystemEvent(
                "zone.config.updated",
                "MultiZoneManager", 
                {"zone_id": zone_id, "updates": updates}
            ))
            
            self._logger.info("Zone config updated", zone_id=zone_id, updates=updates)
            return True
            
        except Exception as e:
            self._logger.error("Failed to update zone config", zone_id=zone_id, error=str(e))
            return False
    
    def get_system_summary(self) -> Dict[str, Any]:
        """Get system-wide summary."""
        total_zones = len(self._zones)
        enabled_zones = sum(1 for config in self._zones.values() if config.enabled)
        alarm_zones = sum(1 for status in self._zone_statuses.values() 
                         if status.controller_status.alarm)
        
        return {
            "total_zones": total_zones,
            "enabled_zones": enabled_zones,
            "alarm_zones": alarm_zones,
            "scheduler_stats": self._scheduler.get_stats(),
            "uptime_ms": self.clock.now_ms()
        }
    
    def _handle_zone_config_update(self, event: SystemEvent) -> None:
        """Handle zone configuration update events."""
        zone_id = event.data.get("zone_id")
        if zone_id and zone_id in self._zones:
            self._logger.info("Received zone config update", zone_id=zone_id)
    
    def _handle_system_shutdown(self, event: SystemEvent) -> None:
        """Handle system shutdown event."""
        self._logger.info("System shutdown - putting all zones in safe state")
        for controller in self._controllers.values():
            try:
                controller.force_safe_state()
            except Exception as e:
                self._logger.error("Error during zone shutdown", error=str(e))
    
    def _log_system_stats(self) -> None:
        """Log periodic system statistics."""
        summary = self.get_system_summary()
        self._logger.info("Multi-zone system stats",
                        total_zones=summary["total_zones"],
                        enabled_zones=summary["enabled_zones"],
                        alarm_zones=summary["alarm_zones"],
                        avg_cycle_time_ms=summary["scheduler_stats"]["avg_cycle_time_ms"])
    
    def shutdown(self) -> None:
        """Graceful shutdown of multi-zone system.""" 
        self.event_bus.publish(SystemEvent("system.shutdown", "MultiZoneManager"))
        
        for zone_id, controller in self._controllers.items():
            try:
                controller.force_safe_state()
                controller.close()
            except Exception as e:
                self._logger.error("Error shutting down zone", zone_id=zone_id, error=str(e))
        
        self._logger.info("Multi-zone manager shutdown complete")
