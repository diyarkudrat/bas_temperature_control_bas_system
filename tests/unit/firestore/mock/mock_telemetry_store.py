"""Mock Firestore telemetry data access layer with repository pattern."""

import time
import logging
from typing import List, Dict, Any, Optional
from unittest.mock import Mock

from .mock_base import MockTenantTimestampedRepository, MockQueryOptions, MockPaginatedResult, MockOperationResult
from .mock_models import MockTelemetryRecord, create_mock_telemetry_record

logger = logging.getLogger(__name__)


class MockTelemetryRepository(MockTenantTimestampedRepository):
    """Mock telemetry repository with multi-tenant support and timestamping."""
    
    def __init__(self, client: Mock):
        """Initialize with mock Firestore client."""
        super().__init__(client, 'telemetry')
        self.required_fields = ['tenant_id', 'device_id', 'temp_tenths', 'sensor_ok']
    
    def create(self, entity: MockTelemetryRecord) -> MockOperationResult[str]:
        """Create a new telemetry record."""
        try:
            # Validate entity
            self._validate_required_fields(entity.to_dict(), self.required_fields)
            
            # Ensure tenant isolation
            data = self._enforce_tenant_isolation(entity.tenant_id, entity.to_dict())
            
            # Add timestamps
            data = self._add_timestamps(data)
            
            # Add document with auto-generated ID
            doc_ref = self.collection.add(data)
            doc_id = doc_ref[1].id
            
            self.logger.debug(f"Created telemetry record {doc_id} for {entity.tenant_id}/{entity.device_id}")
            return MockOperationResult(success=True, data=doc_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("create telemetry", e)
    
    def get_by_id(self, entity_id: str) -> MockOperationResult[MockTelemetryRecord]:
        """Get telemetry record by ID."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return MockOperationResult(success=False, error="Record not found", error_code="NOT_FOUND")
            
            data = doc.to_dict()
            record = create_mock_telemetry_record(data)
            record.id = doc.id
            
            return MockOperationResult(success=True, data=record)
            
        except Exception as e:
            self._handle_mock_firestore_error("get telemetry by id", e)
    
    def update(self, entity_id: str, updates: Dict[str, Any]) -> MockOperationResult[MockTelemetryRecord]:
        """Update telemetry record."""
        try:
            # Add update timestamp
            updates = self._add_timestamps(updates, include_updated=True)
            
            doc_ref = self.collection.document(entity_id)
            doc_ref.update(updates)
            
            # Return updated record
            return self.get_by_id(entity_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("update telemetry", e)
    
    def delete(self, entity_id: str) -> MockOperationResult[bool]:
        """Delete telemetry record."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc_ref.delete()
            
            self.logger.debug(f"Deleted telemetry record {entity_id}")
            return MockOperationResult(success=True, data=True)
            
        except Exception as e:
            self._handle_mock_firestore_error("delete telemetry", e)
    
    # Advanced query methods
    def query_recent_for_device(self, tenant_id: str, device_id: str, 
                               options: MockQueryOptions = None) -> MockPaginatedResult[MockTelemetryRecord]:
        """Query recent telemetry for a specific device."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'device_id': device_id
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query recent for device", e)
    
    def query_by_timestamp_range(self, tenant_id: str, device_id: str, 
                                start_time_ms: int, end_time_ms: int,
                                options: MockQueryOptions = None) -> MockPaginatedResult[MockTelemetryRecord]:
        """Query telemetry within a timestamp range."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'device_id': device_id,
                'timestamp_ms': ('>=', start_time_ms),
                'timestamp_ms': ('<=', end_time_ms)
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'ASCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query by timestamp range", e)
    
    def query_by_temperature_range(self, tenant_id: str, device_id: str,
                                  min_temp: int, max_temp: int,
                                  options: MockQueryOptions = None) -> MockPaginatedResult[MockTelemetryRecord]:
        """Query telemetry within a temperature range."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'device_id': device_id,
                'temp_tenths': ('>=', min_temp),
                'temp_tenths': ('<=', max_temp)
            }
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query by temperature range", e)
    
    def query_by_state(self, tenant_id: str, device_id: str, state: str,
                      options: MockQueryOptions = None) -> MockPaginatedResult[MockTelemetryRecord]:
        """Query telemetry by device state."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'device_id': device_id,
                'state': state
            }
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query by state", e)
    
    def query_sensor_failures(self, tenant_id: str, device_id: str = None,
                             options: MockQueryOptions = None) -> MockPaginatedResult[MockTelemetryRecord]:
        """Query telemetry records with sensor failures."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'sensor_ok': False
            }
            
            if device_id:
                options.filters['device_id'] = device_id
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query sensor failures", e)
    
    def query_active_devices(self, tenant_id: str, options: MockQueryOptions = None) -> MockPaginatedResult[MockTelemetryRecord]:
        """Query recent telemetry for all active devices."""
        try:
            options = options or MockQueryOptions()
            
            # Get recent timestamp (last hour)
            recent_time = int(time.time() * 1000) - 3600000  # 1 hour ago
            
            options.filters = {
                'tenant_id': tenant_id,
                'timestamp_ms': ('>=', recent_time)
            }
            
            if not options.order_by:
                options.order_by = 'timestamp_ms'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("query active devices", e)
    
    def get_latest_for_device(self, tenant_id: str, device_id: str) -> MockOperationResult[MockTelemetryRecord]:
        """Get the latest telemetry record for a device."""
        try:
            options = MockQueryOptions(limit=1, order_by='timestamp_ms', order_direction='DESCENDING')
            result = self.query_recent_for_device(tenant_id, device_id, options)
            
            if result.items:
                return MockOperationResult(success=True, data=result.items[0])
            else:
                return MockOperationResult(success=False, error="No telemetry found", error_code="NOT_FOUND")
                
        except Exception as e:
            self._handle_mock_firestore_error("get latest for device", e)
    
    def get_statistics_for_device(self, tenant_id: str, device_id: str, 
                                 start_time_ms: int, end_time_ms: int) -> MockOperationResult[Dict[str, Any]]:
        """Get statistics for a device over a time period."""
        try:
            options = MockQueryOptions(limit=1000)  # Get all records in range
            result = self.query_by_timestamp_range(tenant_id, device_id, start_time_ms, end_time_ms, options)
            
            if not result.items:
                return MockOperationResult(success=False, error="No data found", error_code="NOT_FOUND")
            
            records = result.items
            
            # Calculate statistics
            temps = [r.temp_tenths for r in records]
            setpoints = [r.setpoint_tenths for r in records]
            
            stats = {
                'record_count': len(records),
                'temp_min': min(temps),
                'temp_max': max(temps),
                'temp_avg': sum(temps) / len(temps),
                'setpoint_min': min(setpoints),
                'setpoint_max': max(setpoints),
                'setpoint_avg': sum(setpoints) / len(setpoints),
                'cool_active_count': sum(1 for r in records if r.cool_active),
                'heat_active_count': sum(1 for r in records if r.heat_active),
                'sensor_failures': sum(1 for r in records if not r.sensor_ok),
                'start_time_ms': start_time_ms,
                'end_time_ms': end_time_ms
            }
            
            return MockOperationResult(success=True, data=stats)
            
        except Exception as e:
            self._handle_mock_firestore_error("get statistics for device", e)
    
    def _execute_query(self, options: MockQueryOptions) -> MockPaginatedResult[MockTelemetryRecord]:
        """Execute a query with the given options."""
        query = self.collection
        
        # Apply query options
        query = self._apply_query_options(query, options)
        
        # Execute query
        docs = list(query.stream())
        
        # Convert to telemetry records
        records = []
        for doc in docs:
            data = doc.to_dict()
            record = create_mock_telemetry_record(data)
            record.id = doc.id
            records.append(record)
        
        # Check if there are more results
        has_more = len(docs) == options.limit
        next_offset = docs[-1].id if has_more and docs else None
        
        return MockPaginatedResult(
            items=records,
            has_more=has_more,
            next_offset=next_offset
        )
    
    # Legacy compatibility methods
    def add_telemetry(self, tenant_id: str, device_id: str, data: Dict[str, Any]) -> bool:
        """Legacy method for adding telemetry data."""
        try:
            # Convert legacy data format to MockTelemetryRecord
            telemetry_data = {
                'tenant_id': tenant_id,
                'device_id': device_id,
                'timestamp_ms': data.get('timestamp', int(time.time() * 1000)),
                'utc_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'temp_tenths': data.get('temp_tenths', 0),
                'setpoint_tenths': data.get('setpoint_tenths', 0),
                'deadband_tenths': data.get('deadband_tenths', 0),
                'cool_active': data.get('cool_active', False),
                'heat_active': data.get('heat_active', False),
                'state': data.get('state', 'IDLE'),
                'sensor_ok': data.get('sensor_ok', True)
            }
            
            record = create_mock_telemetry_record(telemetry_data)
            result = self.create(record)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Error in legacy add_telemetry: {e}")
            return False
    
    def query_recent(self, tenant_id: str, device_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Legacy method for querying recent telemetry."""
        try:
            options = MockQueryOptions(limit=limit, order_by='timestamp_ms', order_direction='DESCENDING')
            result = self.query_recent_for_device(tenant_id, device_id, options)
            
            # Convert to legacy format
            return [record.to_dict() for record in result.items]
            
        except Exception as e:
            self.logger.error(f"Error in legacy query_recent: {e}")
            return []
    
    def query_window(self, tenant_id: str, device_id: str, start_time: int, end_time: int, limit: int = 1000) -> List[Dict[str, Any]]:
        """Legacy method for querying telemetry within a time window."""
        try:
            options = MockQueryOptions(limit=limit)
            result = self.query_by_timestamp_range(tenant_id, device_id, start_time, end_time, options)
            
            # Convert to legacy format
            return [record.to_dict() for record in result.items]
            
        except Exception as e:
            self.logger.error(f"Error in legacy query_window: {e}")
            return []
    
    def query_recent_paginated(self, tenant_id: str, device_id: str, limit: int = 100) -> Dict[str, Any]:
        """Legacy method for paginated recent telemetry query."""
        try:
            options = MockQueryOptions(limit=limit, order_by='timestamp_ms', order_direction='DESCENDING')
            result = self.query_recent_for_device(tenant_id, device_id, options)
            
            # Convert to legacy format
            return {
                'data': [record.to_dict() for record in result.items],
                'has_more': result.has_more,
                'last_doc_id': result.next_offset
            }
            
        except Exception as e:
            self.logger.error(f"Error in legacy query_recent_paginated: {e}")
            return {'data': [], 'has_more': False, 'last_doc_id': None}
    
    def get_device_statistics(self, tenant_id: str, device_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get device statistics for the specified number of hours."""
        try:
            end_time = int(time.time() * 1000)
            start_time = end_time - (hours * 3600 * 1000)
            
            result = self.get_statistics_for_device(tenant_id, device_id, start_time, end_time)
            
            if not result.success:
                return {
                    'total_records': 0,
                    'avg_temperature': 0,
                    'min_temperature': 0,
                    'max_temperature': 0,
                    'sensor_failures': 0,
                    'uptime_percentage': 0
                }
            
            stats = result.data
            
            # Calculate uptime percentage (records with sensor_ok=True)
            total_records = stats['record_count']
            sensor_failures = stats['sensor_failures']
            uptime_percentage = ((total_records - sensor_failures) / total_records * 100) if total_records > 0 else 0
            
            return {
                'total_records': total_records,
                'avg_temperature': round(stats['temp_avg'], 2),
                'min_temperature': stats['temp_min'],
                'max_temperature': stats['temp_max'],
                'sensor_failures': sensor_failures,
                'uptime_percentage': round(uptime_percentage, 2)
            }
            
        except Exception as e:
            self.logger.error(f"Error in get_device_statistics: {e}")
            return {
                'total_records': 0,
                'avg_temperature': 0,
                'min_temperature': 0,
                'max_temperature': 0,
                'sensor_failures': 0,
                'uptime_percentage': 0
            }
    
    def query_time_window(self, tenant_id: str, device_id: str, start_time: int, end_time: int, options: MockQueryOptions = None) -> MockPaginatedResult[MockTelemetryRecord]:
        """Query telemetry within a time window (alias for query_by_timestamp_range)."""
        return self.query_by_timestamp_range(tenant_id, device_id, start_time, end_time, options)
    
    def get_device_count(self, tenant_id: str) -> int:
        """Get count of unique devices for a tenant."""
        try:
            # Query all telemetry records for the tenant
            options = MockQueryOptions(limit=1000)
            options.filters = {'tenant_id': tenant_id}
            
            query = self._apply_query_options(self.collection, options)
            docs = list(query.stream())
            
            # Extract unique device IDs
            device_ids = set()
            for doc in docs:
                data = doc.to_dict()
                if 'device_id' in data:
                    device_ids.add(data['device_id'])
            
            return len(device_ids)
            
        except Exception as e:
            self.logger.error(f"Error in get_device_count: {e}")
            return 0


# Backward compatibility alias
MockTelemetryStore = MockTelemetryRepository
