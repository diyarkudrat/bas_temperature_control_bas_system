# blueprints/telemetry.py
# Telemetry and analytics blueprint implementation

import time
import ujson as json
# typing removed for MicroPython
from dataclasses import dataclass, field
from services import Logger, LoggerFactory, SystemError, SystemErrorCodes
from interfaces import Clock

@dataclass
class TelemetryPoint:
    """Single telemetry data point."""
    timestamp_ms: int
    metric_name: str
    value: Union[float, int, str, bool]
    unit: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp_ms": self.timestamp_ms,
            "metric": self.metric_name,
            "value": self.value,
            "unit": self.unit,
            "tags": self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TelemetryPoint':
        """Create from dictionary."""
        return cls(
            timestamp_ms=data["timestamp_ms"],
            metric_name=data["metric"],
            value=data["value"],
            unit=data.get("unit", ""),
            tags=data.get("tags", {})
        )

@dataclass
class TelemetryBatch:
    """Batch of telemetry points for efficient transmission."""
    points: List[TelemetryPoint]
    batch_id: str
    created_ms: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert batch to dictionary."""
        return {
            "batch_id": self.batch_id,
            "created_ms": self.created_ms,
            "metadata": self.metadata,
            "points": [point.to_dict() for point in self.points]
        }
    
    def size_bytes(self) -> int:
        """Estimate batch size in bytes."""
        return len(json.dumps(self.to_dict()))

class TelemetryCollector:
    """Collects telemetry data from various sources."""
    
    def __init__(self, clock: Clock):
        self.clock = clock
        self._logger = LoggerFactory.get_logger("TelemetryCollector")
        self._collectors: Dict[str, Callable[[], List[TelemetryPoint]]] = {}
        self._collection_count = 0
    
    def register_collector(self, name: str, collector_func: Callable[[], List[TelemetryPoint]]) -> None:
        """Register a telemetry collector function."""
        self._collectors[name] = collector_func
        self._logger.debug("Registered telemetry collector", name=name)
    
    def collect_all(self) -> List[TelemetryPoint]:
        """Collect telemetry from all registered collectors."""
        all_points = []
        self._collection_count += 1
        
        for name, collector in self._collectors.items():
            try:
                points = collector()
                all_points.extend(points)
                
                if self._collection_count % 100 == 0:  # Log periodically
                    self._logger.debug("Collector stats", name=name, points_collected=len(points))
                    
            except Exception as e:
                self._logger.error("Telemetry collector failed", name=name, error=str(e))
        
        return all_points
    
    def create_system_collector(self, system_manager) -> Callable[[], List[TelemetryPoint]]:
        """Create collector for system-wide metrics."""
        def collect_system_metrics() -> List[TelemetryPoint]:
            points = []
            timestamp = self.clock.now_ms()
            
            try:
                # System uptime
                points.append(TelemetryPoint(
                    timestamp_ms=timestamp,
                    metric_name="system.uptime_ms",
                    value=timestamp,
                    unit="ms",
                    tags={"source": "system"}
                ))
                
                # Memory usage (if available)
                try:
                    import gc
                    mem_free = gc.mem_free()
                    mem_alloc = gc.mem_alloc()
                    
                    points.append(TelemetryPoint(
                        timestamp_ms=timestamp,
                        metric_name="system.memory.free",
                        value=mem_free,
                        unit="bytes",
                        tags={"source": "system"}
                    ))
                    
                    points.append(TelemetryPoint(
                        timestamp_ms=timestamp,
                        metric_name="system.memory.allocated",
                        value=mem_alloc,
                        unit="bytes",
                        tags={"source": "system"}
                    ))
                except:
                    pass  # Memory info not available
                
                # System summary (if available)
                if hasattr(system_manager, 'get_system_summary'):
                    summary = system_manager.get_system_summary()
                    
                    for key, value in summary.items():
                        if isinstance(value, (int, float)):
                            points.append(TelemetryPoint(
                                timestamp_ms=timestamp,
                                metric_name=f"system.{key}",
                                value=value,
                                tags={"source": "system"}
                            ))
                
            except Exception as e:
                self._logger.error("System metrics collection failed", error=str(e))
            
            return points
        
        return collect_system_metrics
    
    def create_zone_collector(self, zone_manager) -> Callable[[], List[TelemetryPoint]]:
        """Create collector for zone metrics."""
        def collect_zone_metrics() -> List[TelemetryPoint]:
            points = []
            timestamp = self.clock.now_ms()
            
            try:
                if hasattr(zone_manager, 'get_all_zone_statuses'):
                    zone_statuses = zone_manager.get_all_zone_statuses()
                    
                    for zone_id, status in zone_statuses.items():
                        tags = {"zone_id": zone_id, "zone_name": status.name}
                        
                        # Temperature metrics
                        if status.controller_status.temp_tenths is not None:
                            points.append(TelemetryPoint(
                                timestamp_ms=timestamp,
                                metric_name="zone.temperature",
                                value=status.controller_status.temp_tenths / 10.0,
                                unit="celsius",
                                tags=tags
                            ))
                        
                        # Setpoint
                        points.append(TelemetryPoint(
                            timestamp_ms=timestamp,
                            metric_name="zone.setpoint",
                            value=status.controller_status.setpoint_tenths / 10.0,
                            unit="celsius",
                            tags=tags
                        ))
                        
                        # Actuator states
                        points.append(TelemetryPoint(
                            timestamp_ms=timestamp,
                            metric_name="zone.cooling_active",
                            value=1 if status.controller_status.cool_active else 0,
                            unit="boolean",
                            tags=tags
                        ))
                        
                        points.append(TelemetryPoint(
                            timestamp_ms=timestamp,
                            metric_name="zone.heating_active", 
                            value=1 if status.controller_status.heat_active else 0,
                            unit="boolean",
                            tags=tags
                        ))
                        
                        # State and alarms
                        points.append(TelemetryPoint(
                            timestamp_ms=timestamp,
                            metric_name="zone.alarm",
                            value=1 if status.controller_status.alarm else 0,
                            unit="boolean",
                            tags=tags
                        ))
                        
                        if status.controller_status.error_code > 0:
                            points.append(TelemetryPoint(
                                timestamp_ms=timestamp,
                                metric_name="zone.error_code",
                                value=status.controller_status.error_code,
                                tags=tags
                            ))
                        
                        # Error counts
                        points.append(TelemetryPoint(
                            timestamp_ms=timestamp,
                            metric_name="zone.error_count",
                            value=status.error_count,
                            tags=tags
                        ))
                
            except Exception as e:
                self._logger.error("Zone metrics collection failed", error=str(e))
            
            return points
        
        return collect_zone_metrics

class TelemetryBuffer:
    """Buffer for telemetry data with different storage strategies."""
    
    def __init__(self, max_points: int = 1000, max_batches: int = 10):
        self.max_points = max_points
        self.max_batches = max_batches
        self._points: List[TelemetryPoint] = []
        self._batches: List[TelemetryBatch] = []
        self._logger = LoggerFactory.get_logger("TelemetryBuffer")
        self._next_batch_id = 1
    
    def add_points(self, points: List[TelemetryPoint]) -> None:
        """Add points to buffer."""
        self._points.extend(points)
        
        # Trim if over limit
        if len(self._points) > self.max_points:
            overflow = len(self._points) - self.max_points
            self._points = self._points[overflow:]
            self._logger.warning("Telemetry buffer overflow", dropped_points=overflow)
    
    def create_batch(self, max_points: int = None) -> Optional[TelemetryBatch]:
        """Create batch from buffered points."""
        if not self._points:
            return None
        
        # Determine batch size
        batch_size = min(len(self._points), max_points or len(self._points))
        
        # Create batch
        batch_points = self._points[:batch_size]
        batch = TelemetryBatch(
            points=batch_points,
            batch_id=f"batch_{self._next_batch_id}",
            created_ms=time.ticks_ms(),
            metadata={"point_count": len(batch_points)}
        )
        
        # Remove points from buffer
        self._points = self._points[batch_size:]
        self._next_batch_id += 1
        
        # Store batch for retry handling
        self._batches.append(batch)
        if len(self._batches) > self.max_batches:
            self._batches.pop(0)  # Remove oldest
        
        return batch
    
    def get_pending_batches(self) -> List[TelemetryBatch]:
        """Get batches pending export."""
        return self._batches.copy()
    
    def mark_batch_exported(self, batch_id: str) -> bool:
        """Mark batch as successfully exported."""
        for i, batch in enumerate(self._batches):
            if batch.batch_id == batch_id:
                del self._batches[i]
                return True
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        return {
            "buffered_points": len(self._points),
            "pending_batches": len(self._batches),
            "next_batch_id": self._next_batch_id,
            "buffer_utilization": len(self._points) / self.max_points * 100
        }

class TelemetryBackend:
    """Base telemetry backend interface."""
    
    def __init__(self, name: str):
        self.name = name
        self._export_count = 0
        self._error_count = 0
        self._last_export_ms = 0
    
    def export_batch(self, batch: TelemetryBatch) -> bool:
        """Export telemetry batch. Return True on success."""
        raise NotImplementedError
    
    def health_check(self) -> bool:
        """Check backend health."""
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get backend statistics."""
        return {
            "name": self.name,
            "export_count": self._export_count,
            "error_count": self._error_count,
            "last_export_ms": self._last_export_ms,
            "error_rate": self._error_count / max(1, self._export_count) * 100
        }
    
    def _record_export(self, success: bool) -> None:
        """Record export attempt."""
        self._export_count += 1
        self._last_export_ms = time.ticks_ms()
        if not success:
            self._error_count += 1

class CSVTelemetryBackend(TelemetryBackend):
    """CSV file telemetry backend."""
    
    def __init__(self, file_path: str = "/telemetry.csv"):
        super().__init__("CSV")
        self.file_path = file_path
        self._logger = LoggerFactory.get_logger("CSVTelemetryBackend")
        self._initialize_file()
    
    def _initialize_file(self) -> None:
        """Initialize CSV file with headers."""
        try:
            # Check if file exists
            try:
                with open(self.file_path, 'r'):
                    pass  # File exists
            except OSError:
                # File doesn't exist, create with headers
                with open(self.file_path, 'w') as f:
                    f.write("timestamp_ms,metric,value,unit,tags\n")
                self._logger.info("Created telemetry CSV file", path=self.file_path)
        except Exception as e:
            self._logger.error("Failed to initialize CSV file", error=str(e))
    
    def export_batch(self, batch: TelemetryBatch) -> bool:
        """Export batch to CSV file."""
        try:
            with open(self.file_path, 'a') as f:
                for point in batch.points:
                    # Format tags as JSON string
                    tags_str = json.dumps(point.tags) if point.tags else "{}"
                    
                    # Write CSV line
                    line = f"{point.timestamp_ms},{point.metric_name},{point.value},{point.unit},{tags_str}\n"
                    f.write(line)
            
            self._record_export(True)
            self._logger.debug("Exported batch to CSV", 
                             batch_id=batch.batch_id, 
                             points=len(batch.points))
            return True
            
        except Exception as e:
            self._record_export(False)
            self._logger.error("CSV export failed", batch_id=batch.batch_id, error=str(e))
            return False

class HTTPTelemetryBackend(TelemetryBackend):
    """HTTP endpoint telemetry backend."""
    
    def __init__(self, endpoint: str, api_key: str = "", timeout_ms: int = 5000):
        super().__init__("HTTP")
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout_ms = timeout_ms
        self._logger = LoggerFactory.get_logger("HTTPTelemetryBackend")
    
    def export_batch(self, batch: TelemetryBatch) -> bool:
        """Export batch to HTTP endpoint."""
        try:
            import urequests as requests
            
            # Prepare payload
            payload = batch.to_dict()
            headers = {
                'Content-Type': 'application/json'
            }
            
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            # Make HTTP request
            response = requests.post(
                self.endpoint,
                json=payload,
                headers=headers,
                timeout=self.timeout_ms / 1000.0
            )
            
            success = response.status_code == 200
            response.close()
            
            self._record_export(success)
            
            if success:
                self._logger.debug("Exported batch via HTTP", 
                                 batch_id=batch.batch_id,
                                 points=len(batch.points))
                return True
            else:
                self._logger.error("HTTP export failed", 
                                 batch_id=batch.batch_id,
                                 status_code=response.status_code)
                return False
                
        except Exception as e:
            self._record_export(False)
            self._logger.error("HTTP export failed", batch_id=batch.batch_id, error=str(e))
            return False
    
    def health_check(self) -> bool:
        """Check HTTP endpoint health."""
        try:
            import urequests as requests
            response = requests.get(self.endpoint, timeout=2)
            success = response.status_code < 500
            response.close()
            return success
        except:
            return False

class TelemetryManager:
    """Main telemetry system manager."""
    
    def __init__(self, clock: Clock, buffer_size: int = 1000):
        self.clock = clock
        self._collector = TelemetryCollector(clock)
        self._buffer = TelemetryBuffer(buffer_size)
        self._backends: List[TelemetryBackend] = []
        self._logger = LoggerFactory.get_logger("TelemetryManager")
        
        # Configuration
        self._collection_interval_ms = 10000  # 10 seconds
        self._export_interval_ms = 60000      # 1 minute
        self._max_batch_size = 100
        
        # State
        self._last_collection_ms = 0
        self._last_export_ms = 0
        self._enabled = True
    
    def add_backend(self, backend: TelemetryBackend) -> None:
        """Add telemetry backend."""
        self._backends.append(backend)
        self._logger.info("Added telemetry backend", name=backend.name)
    
    def register_collector(self, name: str, collector_func: Callable[[], List[TelemetryPoint]]) -> None:
        """Register telemetry collector."""
        self._collector.register_collector(name, collector_func)
    
    def set_collection_interval(self, interval_ms: int) -> None:
        """Set telemetry collection interval."""
        self._collection_interval_ms = interval_ms
        self._logger.info("Collection interval updated", interval_ms=interval_ms)
    
    def set_export_interval(self, interval_ms: int) -> None:
        """Set telemetry export interval."""
        self._export_interval_ms = interval_ms
        self._logger.info("Export interval updated", interval_ms=interval_ms)
    
    def step(self) -> None:
        """Execute telemetry processing step."""
        if not self._enabled:
            return
        
        current_time = self.clock.now_ms()
        
        # Collection phase
        if self.clock.elapsed_ms(self._last_collection_ms) >= self._collection_interval_ms:
            self._collect_telemetry()
            self._last_collection_ms = current_time
        
        # Export phase
        if self.clock.elapsed_ms(self._last_export_ms) >= self._export_interval_ms:
            self._export_telemetry()
            self._last_export_ms = current_time
    
    def _collect_telemetry(self) -> None:
        """Collect telemetry from all sources."""
        try:
            points = self._collector.collect_all()
            if points:
                self._buffer.add_points(points)
                self._logger.debug("Collected telemetry points", count=len(points))
        except Exception as e:
            self._logger.error("Telemetry collection failed", error=str(e))
    
    def _export_telemetry(self) -> None:
        """Export telemetry to all backends."""
        try:
            # Create batch from buffer
            batch = self._buffer.create_batch(self._max_batch_size)
            if not batch:
                return
            
            # Export to all backends
            success_count = 0
            for backend in self._backends:
                try:
                    if backend.export_batch(batch):
                        success_count += 1
                except Exception as e:
                    self._logger.error("Backend export failed", 
                                     backend=backend.name, error=str(e))
            
            # Mark as exported if at least one backend succeeded
            if success_count > 0:
                self._buffer.mark_batch_exported(batch.batch_id)
                self._logger.debug("Telemetry batch exported", 
                                 batch_id=batch.batch_id,
                                 points=len(batch.points),
                                 backends=success_count)
            else:
                self._logger.warning("All telemetry backends failed", 
                                   batch_id=batch.batch_id)
                
        except Exception as e:
            self._logger.error("Telemetry export failed", error=str(e))
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get comprehensive telemetry system statistics."""
        stats = {
            "enabled": self._enabled,
            "collection_interval_ms": self._collection_interval_ms,
            "export_interval_ms": self._export_interval_ms,
            "buffer_stats": self._buffer.get_stats(),
            "backends": [backend.get_stats() for backend in self._backends],
            "last_collection_ms": self._last_collection_ms,
            "last_export_ms": self._last_export_ms
        }
        return stats
    
    def enable(self) -> None:
        """Enable telemetry collection and export."""
        self._enabled = True
        self._logger.info("Telemetry enabled")
    
    def disable(self) -> None:
        """Disable telemetry collection and export."""
        self._enabled = False
        self._logger.info("Telemetry disabled")
    
    def force_export(self) -> bool:
        """Force immediate telemetry export."""
        try:
            self._export_telemetry()
            return True
        except Exception as e:
            self._logger.error("Forced export failed", error=str(e))
            return False
