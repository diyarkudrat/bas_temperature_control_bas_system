"""Mock Firestore devices data access layer with repository pattern."""

import time
import logging
from typing import Dict, Any, Optional, List
from unittest.mock import Mock

from .mock_base import MockTenantTimestampedRepository, MockQueryOptions, MockPaginatedResult, MockOperationResult
from .mock_models import MockDevice, create_mock_device

logger = logging.getLogger(__name__)


class MockDevicesRepository(MockTenantTimestampedRepository):
    """Mock devices repository with multi-tenant support and timestamping."""
    
    def __init__(self, client: Mock):
        """Initialize with mock Firestore client."""
        super().__init__(client, 'devices')
        self.required_fields = ['tenant_id', 'device_id']
    
    def create(self, entity: MockDevice) -> MockOperationResult[str]:
        """Create a new device."""
        try:
            # Validate entity
            self._validate_required_fields(entity.to_dict(), self.required_fields)
            
            # Ensure tenant isolation
            data = self._enforce_tenant_isolation(entity.tenant_id, entity.to_dict())
            
            # Add timestamps
            data = self._add_timestamps(data)
            
            # Create composite document ID
            doc_id = f"{entity.tenant_id}_{entity.device_id}"
            
            # Store device document
            doc_ref = self.collection.document(doc_id)
            doc_ref.set(data)
            
            self.logger.info(f"Created device {entity.device_id} for tenant {entity.tenant_id}")
            return MockOperationResult(success=True, data=doc_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("create device", e)
    
    def get_by_id(self, entity_id: str) -> MockOperationResult[MockDevice]:
        """Get device by composite ID (tenant_id_device_id)."""
        try:
            doc_ref = self.collection.document(entity_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return MockOperationResult(success=False, error="Device not found", error_code="NOT_FOUND")
            
            data = doc.to_dict()
            device = create_mock_device(data)
            device.id = doc.id
            
            return MockOperationResult(success=True, data=device)
            
        except Exception as e:
            self._handle_mock_firestore_error("get device by id", e)
    
    def update(self, entity_id: str, updates: Dict[str, Any]) -> MockOperationResult[MockDevice]:
        """Update device by ID."""
        try:
            # Add update timestamp
            updates = self._add_update_timestamp(updates)
            
            doc_ref = self.collection.document(entity_id)
            doc_ref.update(updates)
            
            # Return updated device
            return self.get_by_id(entity_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("update device", e)
    
    def delete(self, entity_id: str) -> MockOperationResult[bool]:
        """Delete device by ID."""
        try:
            # Check if device exists first
            get_result = self.get_by_id(entity_id)
            if not get_result.success:
                return MockOperationResult(success=False, error="Device not found", error_code="NOT_FOUND")
            
            doc_ref = self.collection.document(entity_id)
            doc_ref.delete()
            
            self.logger.info(f"Deleted device {entity_id}")
            return MockOperationResult(success=True, data=True)
            
        except Exception as e:
            self._handle_mock_firestore_error("delete device", e)
    
    # Device-specific methods
    def get_device(self, tenant_id: str, device_id: str) -> MockOperationResult[MockDevice]:
        """Get device by tenant ID and device ID."""
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.get_by_id(doc_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("get device", e)
    
    def update_device_metadata(self, tenant_id: str, device_id: str, metadata: Dict[str, Any]) -> MockOperationResult[MockDevice]:
        """Update device metadata."""
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.update(doc_id, {'metadata': metadata})
            
        except Exception as e:
            self._handle_mock_firestore_error("update device metadata", e)
    
    def update_last_seen(self, tenant_id: str, device_id: str) -> MockOperationResult[MockDevice]:
        """Update device's last seen timestamp."""
        try:
            doc_id = f"{tenant_id}_{device_id}"
            current_time = int(time.time() * 1000)
            return self.update(doc_id, {'last_seen': current_time})
            
        except Exception as e:
            self._handle_mock_firestore_error("update last seen", e)
    
    def set_status(self, tenant_id: str, device_id: str, status: str) -> MockOperationResult[MockDevice]:
        """Set device status."""
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.update(doc_id, {'status': status})
            
        except Exception as e:
            self._handle_mock_firestore_error("set status", e)
    
    def delete_device(self, tenant_id: str, device_id: str) -> MockOperationResult[bool]:
        """Delete device by tenant ID and device ID."""
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.delete(doc_id)
            
        except Exception as e:
            self._handle_mock_firestore_error("delete device", e)
    
    def list_for_tenant(self, tenant_id: str, options: MockQueryOptions = None) -> MockOperationResult[MockPaginatedResult[MockDevice]]:
        """List devices for a tenant."""
        try:
            options = options or MockQueryOptions()
            options.filters = {'tenant_id': tenant_id}
            
            if not options.order_by:
                options.order_by = 'created_at'
                options.order_direction = 'DESCENDING'
            
            result = self._execute_query(options)
            return MockOperationResult(success=True, data=result)
            
        except Exception as e:
            self._handle_mock_firestore_error("list for tenant", e)
    
    def get_by_status(self, tenant_id: str, status: str, options: MockQueryOptions = None) -> MockOperationResult[MockPaginatedResult[MockDevice]]:
        """Get devices by status."""
        try:
            options = options or MockQueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'status': status
            }
            
            if not options.order_by:
                options.order_by = 'last_seen'
                options.order_direction = 'DESCENDING'
            
            result = self._execute_query(options)
            return MockOperationResult(success=True, data=result)
            
        except Exception as e:
            self._handle_mock_firestore_error("get by status", e)
    
    def get_inactive_devices(self, tenant_id: str, inactive_threshold_ms: int = 3600000,
                            options: MockQueryOptions = None) -> MockOperationResult[MockPaginatedResult[MockDevice]]:
        """Get devices that haven't been seen recently."""
        try:
            options = options or MockQueryOptions()
            current_time = int(time.time() * 1000)
            threshold_time = current_time - inactive_threshold_ms
            
            options.filters = {
                'tenant_id': tenant_id,
                'last_seen': ('<', threshold_time)
            }
            
            if not options.order_by:
                options.order_by = 'last_seen'
                options.order_direction = 'ASCENDING'
            
            result = self._execute_query(options)
            return MockOperationResult(success=True, data=result)
            
        except Exception as e:
            self._handle_mock_firestore_error("get inactive devices", e)
    
    def get_online_devices(self, tenant_id: str, options: MockQueryOptions = None) -> MockPaginatedResult[MockDevice]:
        """Get devices that are currently online."""
        try:
            options = options or MockQueryOptions()
            current_time = int(time.time() * 1000)
            one_hour_ago = current_time - 3600000  # 1 hour ago
            
            options.filters = {
                'tenant_id': tenant_id,
                'last_seen': ('>', one_hour_ago)
            }
            
            if not options.order_by:
                options.order_by = 'last_seen'
                options.order_direction = 'DESCENDING'
            
            return self._execute_query(options)
            
        except Exception as e:
            self._handle_mock_firestore_error("get online devices", e)
    
    def check_exists(self, tenant_id: str, device_id: str) -> MockOperationResult[bool]:
        """Check if device exists."""
        try:
            result = self.get_device(tenant_id, device_id)
            return MockOperationResult(success=True, data=result.success)
            
        except Exception as e:
            self._handle_mock_firestore_error("check exists", e)
    
    def get_device_count(self, tenant_id: str) -> MockOperationResult[int]:
        """Get count of devices for a tenant."""
        try:
            query = self.collection.where('tenant_id', '==', tenant_id)
            docs = list(query.stream())
            
            return MockOperationResult(success=True, data=len(docs))
            
        except Exception as e:
            self._handle_mock_firestore_error("get device count", e)
    
    def get_status_summary(self, tenant_id: str) -> MockOperationResult[Dict[str, int]]:
        """Get summary of device statuses for a tenant."""
        try:
            result = self.list_for_tenant(tenant_id, MockQueryOptions(limit=10000))
            
            if not result.success:
                return MockOperationResult(success=False, error=result.error)
            
            status_counts = {}
            for device in result.items:
                status = device.status
                status_counts[status] = status_counts.get(status, 0) + 1
            
            return MockOperationResult(success=True, data=status_counts)
            
        except Exception as e:
            self._handle_mock_firestore_error("get status summary", e)
    
    def search_devices(self, tenant_id: str, search_term: str, options: MockQueryOptions = None) -> MockPaginatedResult[MockDevice]:
        """Search devices by metadata or device ID."""
        try:
            # This is a simplified search implementation
            # In a real implementation, you might use full-text search or multiple queries
            options = options or MockQueryOptions()
            
            # Get all devices for tenant and filter in memory (simplified approach)
            all_devices_result = self.list_for_tenant(tenant_id, MockQueryOptions(limit=10000))
            
            if not all_devices_result.success:
                return MockPaginatedResult(items=[], has_more=False)
            
            # Filter devices that match search term
            matching_devices = []
            search_lower = search_term.lower()
            
            for device in all_devices_result.items:
                # Check device_id
                if search_lower in device.device_id.lower():
                    matching_devices.append(device)
                    continue
                
                # Check metadata values
                for key, value in device.metadata.items():
                    if isinstance(value, str) and search_lower in value.lower():
                        matching_devices.append(device)
                        break
            
            # Apply pagination to results
            start_idx = 0
            if options.offset:
                # Find offset in matching devices
                for i, device in enumerate(matching_devices):
                    if device.id == options.offset:
                        start_idx = i + 1
                        break
            
            end_idx = start_idx + options.limit
            paginated_devices = matching_devices[start_idx:end_idx]
            
            has_more = end_idx < len(matching_devices)
            next_offset = paginated_devices[-1].id if has_more and paginated_devices else None
            
            return MockPaginatedResult(
                items=paginated_devices,
                has_more=has_more,
                next_offset=next_offset
            )
            
        except Exception as e:
            self._handle_mock_firestore_error("search devices", e)
    
    def _add_update_timestamp(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Add update timestamp to the updates dictionary."""
        now = time.time()
        timestamps = self._normalize_timestamp(now)
        updates['updated_at'] = timestamps['timestamp_ms']
        return updates
    
    def _build_query(self, tenant_id: str, options: MockQueryOptions = None) -> Mock:
        """Build a query for the given tenant and options."""
        query = self.collection.where('tenant_id', '==', tenant_id)
        
        if options:
            # Apply additional filters
            if options.filters:
                for field, value in options.filters.items():
                    if field != 'tenant_id':  # Already handled above
                        if isinstance(value, tuple) and len(value) == 2:
                            operator, val = value
                            query = query.where(field, operator, val)
                        else:
                            query = query.where(field, '==', value)
            
            # Apply ordering
            if options.order_by:
                direction = "ASCENDING" if options.order_direction == "ASCENDING" else "DESCENDING"
                query = query.order_by(options.order_by, direction=direction)
            
            # Apply limit
            if options.limit:
                query = query.limit(options.limit)
        
        return query

    def _execute_query(self, options: MockQueryOptions) -> MockPaginatedResult[MockDevice]:
        """Execute a query with the given options."""
        # Build the query step by step to ensure proper mocking
        query = self.collection
        
        # Apply tenant filter first
        if options.filters and 'tenant_id' in options.filters:
            query = query.where('tenant_id', '==', options.filters['tenant_id'])
        
        # Apply other filters
        if options.filters:
            for field, value in options.filters.items():
                if field != 'tenant_id':
                    if isinstance(value, tuple) and len(value) == 2:
                        operator, val = value
                        query = query.where(field, operator, val)
                    else:
                        query = query.where(field, '==', value)
        
        # Apply ordering
        if options.order_by:
            direction = "ASCENDING" if options.order_direction == "ASCENDING" else "DESCENDING"
            query = query.order_by(options.order_by, direction=direction)
        
        # Apply limit
        if options.limit:
            query = query.limit(options.limit)
        
        # Execute query
        docs = list(query.stream())
        
        # Convert to devices
        devices = []
        for doc in docs:
            data = doc.to_dict()
            device = create_mock_device(data)
            device.id = doc.id
            devices.append(device)
        
        # Check if there are more results
        has_more = len(docs) == options.limit
        next_offset = docs[-1].id if has_more and docs else None
        
        return MockPaginatedResult(
            items=devices,
            has_more=has_more,
            next_offset=next_offset
        )


# Backward compatibility alias
MockDevicesStore = MockDevicesRepository
