"""Firestore devices data access layer."""

import time
import logging
from typing import Dict, Any, Optional, List
from google.cloud import firestore
from google.api_core.exceptions import NotFound, PermissionDenied

from .base import OperationResult, PaginatedResult, QueryOptions, TenantAwareRepository, TimestampedRepository
from .models import Device

logger = logging.getLogger(__name__)


class DevicesStore(TenantAwareRepository[Device, str], TimestampedRepository[Device, str]):
    """Firestore-based devices data store."""

    def __init__(self, client: firestore.Client):
        """Initialize with Firestore client."""
        super().__init__(client, 'devices')
        self.required_fields = ['tenant_id', 'device_id']
        
    def create(self, entity: Device) -> OperationResult[str]:
        """
        Create a new device.

        Args:
            entity: Device entity to create

        Returns:
            OperationResult with device ID on success
        """
        try:
            # Validate required fields
            entity_dict = entity.to_dict()
            if not entity.tenant_id or not entity.device_id:
                raise ValueError("tenant_id and device_id are required")

            # Enforce tenant isolation
            data = self._enforce_tenant_isolation(entity.tenant_id, entity_dict)

            # Add timestamps
            data = self._add_timestamps(data)

            # Create composite document ID
            doc_id = f"{entity.tenant_id}_{entity.device_id}"

            # Store device document
            doc_ref = self.collection.document(doc_id)
            doc_ref.set(data)

            self.logger.info(f"Created device {entity.device_id} for tenant {entity.tenant_id}")
            return OperationResult(success=True, data=doc_id)

        except PermissionDenied as e:
            self.logger.error(f"Permission denied creating device: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to create device: {e}")
            return OperationResult(success=False, error=str(e), error_code="CREATE_FAILED")
    
    def get_by_id(self, entity_id: str) -> OperationResult[Device]:
        """
        Get device by composite ID (tenant_id_device_id).

        Args:
            entity_id: Composite device ID

        Returns:
            OperationResult with Device entity on success
        """
        try:
            doc_ref = self.collection.document(entity_id)
            doc = doc_ref.get()

            if not doc.exists:
                return OperationResult(success=False, error="Device not found", error_code="NOT_FOUND")

            data = doc.to_dict()
            device = Device.from_dict(data)
            device.id = doc.id

            return OperationResult(success=True, data=device)

        except PermissionDenied as e:
            self.logger.error(f"Permission denied getting device by id: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to get device by id {entity_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="GET_FAILED")
    
    def update(self, entity_id: str, updates: Dict[str, Any]) -> OperationResult[Device]:
        """
        Update device by ID.

        Args:
            entity_id: Composite device ID
            updates: Dictionary of fields to update

        Returns:
            OperationResult with updated Device entity on success
        """
        try:
            # Add update timestamp
            updates = self._add_update_timestamp(updates)

            doc_ref = self.collection.document(entity_id)
            doc_ref.update(updates)

            # Return updated device
            return self.get_by_id(entity_id)

        except PermissionDenied as e:
            self.logger.error(f"Permission denied updating device: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to update device {entity_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="UPDATE_FAILED")
    
    def delete(self, entity_id: str) -> OperationResult[bool]:
        """
        Delete device by ID.

        Args:
            entity_id: Composite device ID

        Returns:
            OperationResult with success boolean
        """
        try:
            # Check if device exists first
            get_result = self.get_by_id(entity_id)
            if not get_result.success:
                return OperationResult(success=False, error="Device not found", error_code="NOT_FOUND")

            doc_ref = self.collection.document(entity_id)
            doc_ref.delete()

            self.logger.info(f"Deleted device {entity_id}")
            return OperationResult(success=True, data=True)

        except PermissionDenied as e:
            self.logger.error(f"Permission denied deleting device: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to delete device {entity_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="DELETE_FAILED")
    
    def get_device(self, tenant_id: str, device_id: str) -> OperationResult[Device]:
        """
        Get device by tenant ID and device ID.

        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier

        Returns:
            OperationResult with Device entity on success
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.get_by_id(doc_id)

        except Exception as e:
            self.logger.error(f"Failed to get device {device_id} for tenant {tenant_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="GET_FAILED")

    def update_device_metadata(self, tenant_id: str, device_id: str, metadata: Dict[str, Any]) -> OperationResult[Device]:
        """
        Update device metadata.

        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            metadata: New metadata

        Returns:
            OperationResult with updated Device entity on success
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.update(doc_id, {'metadata': metadata})

        except Exception as e:
            self.logger.error(f"Failed to update device metadata for {device_id} in tenant {tenant_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="UPDATE_FAILED")

    def update_last_seen(self, tenant_id: str, device_id: str) -> OperationResult[Device]:
        """
        Update device's last seen timestamp.

        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier

        Returns:
            OperationResult with updated Device entity on success
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            current_time = int(time.time() * 1000)
            return self.update(doc_id, {'last_seen': current_time})

        except Exception as e:
            self.logger.error(f"Failed to update last seen for {device_id} in tenant {tenant_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="UPDATE_FAILED")

    def set_status(self, tenant_id: str, device_id: str, status: str) -> OperationResult[Device]:
        """
        Set device status.

        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            status: Device status

        Returns:
            OperationResult with updated Device entity on success
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.update(doc_id, {'status': status})

        except Exception as e:
            self.logger.error(f"Failed to set status for {device_id} in tenant {tenant_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="UPDATE_FAILED")

    def delete_device(self, tenant_id: str, device_id: str) -> OperationResult[bool]:
        """
        Delete device by tenant ID and device ID.

        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier

        Returns:
            OperationResult with success boolean
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            return self.delete(doc_id)

        except Exception as e:
            self.logger.error(f"Failed to delete device {device_id} for tenant {tenant_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="DELETE_FAILED")
    
    def list_for_tenant(self, tenant_id: str, options: Optional[QueryOptions] = None) -> OperationResult[PaginatedResult[Device]]:
        """
        List devices for a tenant.

        Args:
            tenant_id: Tenant identifier
            options: Query options (limit, order_by, etc.)

        Returns:
            OperationResult with paginated device results
        """
        try:
            options = options or QueryOptions()
            options.filters = {'tenant_id': tenant_id}

            if not options.order_by:
                options.order_by = 'created_at'
                options.order_direction = 'DESCENDING'

            result = self._execute_query(options)
            return OperationResult(success=True, data=result)

        except PermissionDenied as e:
            self.logger.error(f"Permission denied listing devices for tenant {tenant_id}: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to list devices for tenant {tenant_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="LIST_FAILED")

    def check_exists(self, tenant_id: str, device_id: str) -> OperationResult[bool]:
        """
        Check if device exists.

        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier

        Returns:
            OperationResult with existence boolean
        """
        try:
            result = self.get_device(tenant_id, device_id)
            return OperationResult(success=True, data=result.success)

        except Exception as e:
            self.logger.error(f"Failed to check device existence: {e}")
            return OperationResult(success=False, error=str(e), error_code="CHECK_FAILED")
    
    def get_by_status(self, tenant_id: str, status: str, options: Optional[QueryOptions] = None) -> OperationResult[PaginatedResult[Device]]:
        """
        Get devices by status.

        Args:
            tenant_id: Tenant identifier
            status: Device status
            options: Query options

        Returns:
            OperationResult with paginated device results
        """
        try:
            options = options or QueryOptions()
            options.filters = {
                'tenant_id': tenant_id,
                'status': status
            }

            if not options.order_by:
                options.order_by = 'last_seen'
                options.order_direction = 'DESCENDING'

            result = self._execute_query(options)
            return OperationResult(success=True, data=result)

        except PermissionDenied as e:
            self.logger.error(f"Permission denied getting devices by status: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to get devices by status: {e}")
            return OperationResult(success=False, error=str(e), error_code="QUERY_FAILED")
    
    def get_inactive_devices(self, tenant_id: str, inactive_threshold_ms: int = 3600000,
                            options: Optional[QueryOptions] = None) -> OperationResult[PaginatedResult[Device]]:
        """
        Get devices that haven't been seen recently.

        Args:
            tenant_id: Tenant identifier
            inactive_threshold_ms: Threshold in milliseconds (default 1 hour)
            options: Query options

        Returns:
            OperationResult with paginated inactive device results
        """
        try:
            options = options or QueryOptions()
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
            return OperationResult(success=True, data=result)

        except PermissionDenied as e:
            self.logger.error(f"Permission denied getting inactive devices: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to get inactive devices: {e}")
            return OperationResult(success=False, error=str(e), error_code="QUERY_FAILED")

    def get_device_count(self, tenant_id: str) -> OperationResult[int]:
        """
        Get count of devices for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            OperationResult with device count
        """
        try:
            query = self.collection.where('tenant_id', '==', tenant_id)
            docs = list(query.stream())

            return OperationResult(success=True, data=len(docs))

        except PermissionDenied as e:
            self.logger.error(f"Permission denied getting device count: {e}")
            return OperationResult(success=False, error="Permission denied", error_code="PERMISSION_DENIED")
        except Exception as e:
            self.logger.error(f"Failed to get device count for tenant {tenant_id}: {e}")
            return OperationResult(success=False, error=str(e), error_code="COUNT_FAILED")

    def _add_update_timestamp(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Add update timestamp to the updates dictionary."""
        now = time.time()
        timestamps = self._normalize_timestamp(now)
        updates['updated_at'] = timestamps['timestamp_ms']
        return updates

    def _execute_query(self, options: QueryOptions) -> PaginatedResult[Device]:
        """Execute a query with the given options."""
        # Build the query step by step to ensure proper mocking
        query = self.collection

        # Apply query options
        query = self._apply_query_options(query, options)

        # Execute query
        docs = list(query.stream())

        # Convert to devices
        devices = []
        for doc in docs:
            data = doc.to_dict()
            device = Device.from_dict(data)
            device.id = doc.id
            devices.append(device)

        # Check if there are more results
        has_more = len(docs) == options.limit if options.limit else False
        next_offset = docs[-1].id if has_more and docs else None

        return PaginatedResult(
            items=devices,
            has_more=has_more,
            next_offset=next_offset
        )


# Backward compatibility alias
DevicesRepository = DevicesStore
