"""Modern Firestore telemetry data access layer with repository pattern."""

import time
import concurrent.futures
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from google.cloud import firestore
from google.api_core.exceptions import NotFound, PermissionDenied

from .base import TenantAwareRepository, TimestampedRepository, QueryOptions, PaginatedResult, OperationResult
from .models import TelemetryRecord, create_telemetry_record

logger = logging.getLogger(__name__)

DEFAULT_QUERY_TIMEOUT_S = 15


class TelemetryRepository(TenantAwareRepository, TimestampedRepository):
    """Modern telemetry repository with multi-tenant support and timestamping."""
    
    def __init__(self, client: firestore.Client):
        """Initialize with Firestore client."""
        super().__init__(client, 'telemetry')
        self.required_fields = ['tenant_id', 'device_id', 'temp_tenths', 'sensor_ok']
    
    def create(self, entity: TelemetryRecord) -> OperationResult[str]:
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
            return OperationResult(success=True, data=doc_id)
            
        except Exception as e:
            self._handle_firestore_error("create telemetry", e)
    
    def get_by_id(self, entity_id: str) -> OperationResult[TelemetryRecord]:
        """Get telemetry record by ID."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return OperationResult(success=False, error="Record not found", error_code="NOT_FOUND")
            
            data = doc.to_dict()
            record = create_telemetry_record(data)
            record.id = doc.id
            
            return OperationResult(success=True, data=record)
            
        except Exception as e:
            self._handle_firestore_error("get telemetry by id", e)
    
    def update(self, entity_id: str, updates: Dict[str, Any]) -> OperationResult[TelemetryRecord]:
        """Update telemetry record."""
        try:
            # Add update timestamp
            updates = self._add_timestamps(updates, include_updated=True)
            
            doc_ref = self.collection.document(entity_id)
            doc_ref.update(updates)
            
            # Return updated record
            return self.get_by_id(entity_id)
            
        except Exception as e:
            self._handle_firestore_error("update telemetry", e)
    
    def delete(self, entity_id: str) -> OperationResult[bool]:
        """Delete telemetry record."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc_ref.delete()
            
            self.logger.debug(f"Deleted telemetry record {entity_id}")
            return OperationResult(success=True, data=True)
            
        except Exception as e:
            self._handle_firestore_error("delete telemetry", e)
    
    # Advanced query methods
    def query_recent_for_device(self, tenant_id: str, device_id: str,
                               options: QueryOptions = None, timeout_s: Optional[int] = None) -> PaginatedResult[TelemetryRecord]:
        """Query recent telemetry for a specific device."""
        try:
            options = options or QueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'device_id': device_id
            }
            options.order_by = 'timestamp_ms'

            query = self._apply_query_options(self.collection, options)
            return self._execute_query(query, create_telemetry_record,
                                       timeout_s=timeout_s or DEFAULT_QUERY_TIMEOUT_S,
                                       expected_limit=options.limit)

        except Exception as e:
            self._handle_firestore_error("query recent for device", e)
    
    def query_time_window(self, tenant_id: str, device_id: str, start_time_ms: int,
                         end_time_ms: int, options: QueryOptions = None, timeout_s: Optional[int] = None) -> PaginatedResult[TelemetryRecord]:
        """Query telemetry within a time window."""
        try:
            options = options or QueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'device_id': device_id,
                'timestamp_ms': ('>=', start_time_ms),
                'timestamp_ms': ('<=', end_time_ms)
            }
            options.order_by = 'timestamp_ms'

            query = self._apply_query_options(self.collection, options)
            return self._execute_query(query, create_telemetry_record,
                                       timeout_s=timeout_s or DEFAULT_QUERY_TIMEOUT_S,
                                       expected_limit=options.limit)

        except Exception as e:
            self._handle_firestore_error("query time window", e)
    
    def get_device_statistics(self, tenant_id: str, device_id: str,
                             hours: int = 24) -> Dict[str, Any]:
        """Get device statistics for the last N hours."""
        try:
            end_time = int(time.time() * 1000)
            start_time = end_time - (hours * 3600 * 1000)

            # Get detailed statistics from the lower-level method
            stats_result = self.get_statistics_for_device(tenant_id, device_id, start_time, end_time)

            if not stats_result.success:
                return {
                    'total_records': 0,
                    'avg_temperature': 0,
                    'min_temperature': 0,
                    'max_temperature': 0,
                    'sensor_failures': 0,
                    'uptime_percentage': 0
                }

            detailed_stats = stats_result.data

            # Convert detailed stats to the expected format
            total_count = detailed_stats['record_count']
            sensor_failures = detailed_stats['sensor_failures']
            sensor_ok_count = total_count - sensor_failures

            stats = {
                'total_records': total_count,
                'avg_temperature': detailed_stats['temp_avg'],
                'min_temperature': detailed_stats['temp_min'],
                'max_temperature': detailed_stats['temp_max'],
                'sensor_failures': sensor_failures,
                'uptime_percentage': (sensor_ok_count / total_count * 100) if total_count > 0 else 0
            }

            self.logger.debug(f"Generated stats for {tenant_id}/{device_id}: {stats}")
            return stats

        except Exception as e:
            self._handle_firestore_error("get device statistics", e)
    
    # Legacy compatibility methods
    def add_telemetry(self, tenant_id: str, device_id: str, data: Dict[str, Any]) -> bool:
        """Legacy method for adding telemetry data."""
        try:
            # Create TelemetryRecord from legacy data
            timestamp_ms = data.get('timestamp', time.time() * 1000)
            utc_timestamp = datetime.utcfromtimestamp(timestamp_ms / 1000).isoformat() + 'Z'
            
            record = TelemetryRecord(
                tenant_id=tenant_id,
                device_id=device_id,
                timestamp_ms=int(timestamp_ms),
                utc_timestamp=utc_timestamp,
                temp_tenths=data.get('temp_tenths', 0),
                setpoint_tenths=data.get('setpoint_tenths', 230),
                deadband_tenths=data.get('deadband_tenths', 10),
                cool_active=data.get('cool_active', False),
                heat_active=data.get('heat_active', False),
                state=data.get('state', 'IDLE'),
                sensor_ok=data.get('sensor_ok', False)
            )
            
            result = self.create(record)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Failed to add telemetry: {e}")
            return False
    
    def query_recent(self, tenant_id: str, device_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Legacy method for querying recent telemetry data."""
        try:
            options = QueryOptions(limit=limit)
            result = self.query_recent_for_device(tenant_id, device_id, options)
            
            # Convert to legacy format
            legacy_results = []
            for record in result.items:
                data = record.to_dict()
                legacy_results.append(data)
            
            return legacy_results
            
        except Exception as e:
            self.logger.error(f"Failed to query recent telemetry: {e}")
            return []
    
    def query_window(self, tenant_id: str, device_id: str, start_time_ms: int, 
                    end_time_ms: int, limit: int = 1000) -> List[Dict[str, Any]]:
        """Legacy method for querying telemetry within time window."""
        try:
            options = QueryOptions(limit=limit)
            result = self.query_time_window(tenant_id, device_id, start_time_ms, end_time_ms, options)
            
            # Convert to legacy format
            legacy_results = []
            for record in result.items:
                data = record.to_dict()
                legacy_results.append(data)
            
            return legacy_results
            
        except Exception as e:
            self.logger.error(f"Failed to query telemetry window: {e}")
            return []
    
    def query_recent_paginated(self, tenant_id: str, device_id: str, limit: int = 100,
                              start_after_doc_id: Optional[str] = None) -> Dict[str, Any]:
        """Legacy method for paginated telemetry queries."""
        try:
            options = QueryOptions(limit=limit, offset=start_after_doc_id)
            result = self.query_recent_for_device(tenant_id, device_id, options)
            
            # Convert to legacy format
            legacy_data = []
            for record in result.items:
                data = record.to_dict()
                legacy_data.append(data)
            
            return {
                'data': legacy_data,
                'last_doc_id': result.next_offset,
                'has_more': result.has_more
            }
            
        except Exception as e:
            self.logger.error(f"Failed to query paginated telemetry: {e}")
            return {'data': [], 'last_doc_id': None, 'has_more': False}
    
    def get_device_count(self, tenant_id: str) -> int:
        """Get count of unique devices for a tenant."""
        try:
            # Query for distinct device_ids for this tenant
            query = (self.collection
                    .where('tenant_id', '==', tenant_id)
                    .select(['device_id']))

            docs = query.stream()
            device_ids = set()

            for doc in docs:
                data = doc.to_dict()
                device_ids.add(data.get('device_id'))

            count = len(device_ids)
            self.logger.debug(f"Found {count} unique devices for tenant {tenant_id}")
            return count

        except Exception as e:
            self.logger.error(f"Failed to get device count: {e}")
            return 0

    def _execute_query(self, query: firestore.Query, create_record_func,
                       timeout_s: Optional[int] = None,
                       expected_limit: Optional[int] = None) -> PaginatedResult:
        """Execute a Firestore query with optional timeout and return paginated results."""
        try:
            docs = self._stream_with_timeout(query, timeout_s) if timeout_s else query.stream()

            results = []
            last_doc_id = None

            for doc in docs:
                data = doc.to_dict()
                record = create_record_func(data)
                record.id = doc.id
                results.append(record)
                last_doc_id = doc.id

            # Determine has_more based on expected_limit if provided (fallback 100)
            effective_limit = expected_limit if (isinstance(expected_limit, int) and expected_limit > 0) else 100
            has_more = len(results) >= effective_limit
            next_offset = last_doc_id if has_more else None

            return PaginatedResult(
                items=results,
                has_more=has_more,
                next_offset=next_offset
            )

        except TimeoutError as e:
            self.logger.error(f"Query timed out: {e}")
            return PaginatedResult(items=[], has_more=False)
        except Exception as e:
            self.logger.error(f"Failed to execute query: {e}")
            return PaginatedResult(items=[], has_more=False)

    def _stream_with_timeout(self, query: firestore.Query, timeout_s: int):
        """Run query.stream() in a worker thread and enforce a timeout; returns a list of docs."""
        if timeout_s is None or timeout_s <= 0:
            return query.stream()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: list(query.stream()))
            try:
                return future.result(timeout=timeout_s)
            except concurrent.futures.TimeoutError:
                future.cancel()
                raise TimeoutError(f"Firestore query exceeded {timeout_s}s timeout")

    def get_statistics_for_device(self, tenant_id: str, device_id: str, start_time_ms: int, end_time_ms: int) -> OperationResult[Dict[str, Any]]:
        """Get detailed statistics for a device within a time window."""
        try:
            options = QueryOptions(
                limit=1000,
                filters={
                    'tenant_id': tenant_id,
                    'device_id': device_id,
                    'timestamp_ms': ('>=', start_time_ms),
                    'timestamp_ms': ('<=', end_time_ms)
                },
                order_by='timestamp_ms',
                order_direction='DESCENDING'
            )

            query = self._apply_query_options(self.collection, options)
            docs = query.stream()

            records = []
            for doc in docs:
                data = doc.to_dict()
                record = create_telemetry_record(data)
                records.append(record)

            if not records:
                return OperationResult(success=True, data={
                    'record_count': 0,
                    'temp_min': 0,
                    'temp_max': 0,
                    'temp_avg': 0,
                    'setpoint_min': 0,
                    'setpoint_max': 0,
                    'setpoint_avg': 0,
                    'cool_active_count': 0,
                    'heat_active_count': 0,
                    'sensor_failures': 0
                })

            # Calculate detailed statistics
            temps = [r.temp_tenths for r in records if r.sensor_ok]
            setpoints = [r.setpoint_tenths for r in records]
            cool_active = sum(1 for r in records if r.cool_active)
            heat_active = sum(1 for r in records if r.heat_active)
            sensor_failures = sum(1 for r in records if not r.sensor_ok)

            stats = {
                'record_count': len(records),
                'temp_min': min(temps) if temps else 0,
                'temp_max': max(temps) if temps else 0,
                'temp_avg': sum(temps) / len(temps) if temps else 0,
                'setpoint_min': min(setpoints) if setpoints else 0,
                'setpoint_max': max(setpoints) if setpoints else 0,
                'setpoint_avg': sum(setpoints) / len(setpoints) if setpoints else 0,
                'cool_active_count': cool_active,
                'heat_active_count': heat_active,
                'sensor_failures': sensor_failures
            }

            return OperationResult(success=True, data=stats)

        except Exception as e:
            self.logger.error(f"Failed to get statistics for device: {e}")
            return OperationResult(success=False, error=str(e))

    def query_by_timestamp_range(self, tenant_id: str, device_id: str, start_time_ms: int,
                                end_time_ms: int, options: QueryOptions = None) -> PaginatedResult[TelemetryRecord]:
        """Alias for query_time_window for backward compatibility."""
        return self.query_time_window(tenant_id, device_id, start_time_ms, end_time_ms, options)


# Backward compatibility alias
TelemetryStore = TelemetryRepository
