"""Firestore devices data access layer."""

import time
import logging
from typing import Dict, Any, Optional, List
from google.cloud import firestore
from google.cloud.exceptions import NotFound, PermissionDenied

logger = logging.getLogger(__name__)


class DevicesStore:
    """Firestore-based devices data store."""
    
    def __init__(self, client: firestore.Client):
        """Initialize with Firestore client."""
        self.client = client
        self.collection = client.collection('devices')
        
    def register_device(self, tenant_id: str, device_id: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Register a device with metadata.
        
        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            metadata: Device metadata (location, model, notes, etc.)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            current_time = int(time.time() * 1000)
            
            device_doc = {
                'tenant_id': tenant_id,
                'device_id': device_id,
                'metadata': metadata or {},
                'created_at': current_time,
                'last_seen': current_time,
                'status': 'active'
            }
            
            # Use composite key for document ID
            doc_id = f"{tenant_id}_{device_id}"
            doc_ref = self.collection.document(doc_id)
            doc_ref.set(device_doc)
            
            logger.info(f"Registered device {device_id} for tenant {tenant_id}")
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied registering device: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to register device: {e}")
            return False
    
    def get_device(self, tenant_id: str, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Get device information.
        
        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            
        Returns:
            Device document or None if not found
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            doc_ref = self.collection.document(doc_id)
            doc = doc_ref.get()
            
            if doc.exists:
                device_data = doc.to_dict()
                device_data['id'] = doc.id
                return device_data
            else:
                return None
                
        except PermissionDenied as e:
            logger.error(f"Permission denied getting device: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to get device: {e}")
            return None
    
    def update_device_metadata(self, tenant_id: str, device_id: str, metadata: Dict[str, Any]) -> bool:
        """
        Update device metadata.
        
        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            metadata: New metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            doc_ref = self.collection.document(doc_id)
            doc_ref.update({'metadata': metadata})
            
            logger.debug(f"Updated metadata for device {device_id} in tenant {tenant_id}")
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied updating device metadata: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to update device metadata: {e}")
            return False
    
    def update_device_last_seen(self, tenant_id: str, device_id: str) -> bool:
        """
        Update device last seen timestamp.
        
        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            current_time = int(time.time() * 1000)
            doc_id = f"{tenant_id}_{device_id}"
            doc_ref = self.collection.document(doc_id)
            doc_ref.update({'last_seen': current_time})
            
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied updating device last seen: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to update device last seen: {e}")
            return False
    
    def set_device_status(self, tenant_id: str, device_id: str, status: str) -> bool:
        """
        Set device status (active, inactive, maintenance, etc.).
        
        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            status: Device status
            
        Returns:
            True if successful, False otherwise
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            doc_ref = self.collection.document(doc_id)
            doc_ref.update({'status': status})
            
            logger.debug(f"Set status {status} for device {device_id} in tenant {tenant_id}")
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied setting device status: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to set device status: {e}")
            return False
    
    def list_devices_for_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        List all devices for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            List of device documents
        """
        try:
            query = self.collection.where('tenant_id', '==', tenant_id)
            docs = query.stream()
            
            results = []
            for doc in docs:
                device_data = doc.to_dict()
                device_data['id'] = doc.id
                results.append(device_data)
                
            logger.debug(f"Retrieved {len(results)} devices for tenant {tenant_id}")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied listing devices: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to list devices: {e}")
            return []
    
    def delete_device(self, tenant_id: str, device_id: str) -> bool:
        """
        Delete device registration.
        
        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            doc_id = f"{tenant_id}_{device_id}"
            doc_ref = self.collection.document(doc_id)
            doc_ref.delete()
            
            logger.info(f"Deleted device {device_id} for tenant {tenant_id}")
            return True
            
        except PermissionDenied as e:
            logger.error(f"Permission denied deleting device: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to delete device: {e}")
            return False
    
    def check_device_exists(self, tenant_id: str, device_id: str) -> bool:
        """
        Check if device exists for tenant.
        
        Args:
            tenant_id: Tenant identifier
            device_id: Device identifier
            
        Returns:
            True if device exists, False otherwise
        """
        try:
            device = self.get_device(tenant_id, device_id)
            return device is not None
            
        except Exception as e:
            logger.error(f"Failed to check device existence: {e}")
            return False
    
    def get_devices_by_status(self, tenant_id: str, status: str) -> List[Dict[str, Any]]:
        """
        Get devices by status for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            status: Device status to filter by
            
        Returns:
            List of device documents
        """
        try:
            query = (self.collection
                    .where('tenant_id', '==', tenant_id)
                    .where('status', '==', status))
            
            docs = query.stream()
            results = []
            
            for doc in docs:
                device_data = doc.to_dict()
                device_data['id'] = doc.id
                results.append(device_data)
                
            logger.debug(f"Retrieved {len(results)} devices with status {status} for tenant {tenant_id}")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied getting devices by status: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to get devices by status: {e}")
            return []
    
    def get_inactive_devices(self, tenant_id: str, inactive_threshold_ms: int = 3600000) -> List[Dict[str, Any]]:
        """
        Get devices that haven't been seen recently.
        
        Args:
            tenant_id: Tenant identifier
            inactive_threshold_ms: Threshold in milliseconds (default 1 hour)
            
        Returns:
            List of inactive device documents
        """
        try:
            current_time = int(time.time() * 1000)
            threshold_time = current_time - inactive_threshold_ms
            
            query = (self.collection
                    .where('tenant_id', '==', tenant_id)
                    .where('last_seen', '<', threshold_time))
            
            docs = query.stream()
            results = []
            
            for doc in docs:
                device_data = doc.to_dict()
                device_data['id'] = doc.id
                results.append(device_data)
                
            logger.debug(f"Retrieved {len(results)} inactive devices for tenant {tenant_id}")
            return results
            
        except PermissionDenied as e:
            logger.error(f"Permission denied getting inactive devices: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to get inactive devices: {e}")
            return []
