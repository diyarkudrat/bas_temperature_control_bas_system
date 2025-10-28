"""Unit tests for server DevicesStore covering all code paths."""

import time
from unittest.mock import Mock, patch

import pytest
from google.api_core.exceptions import PermissionDenied

from adapters.db.firestore.devices_store import DevicesStore
from adapters.db.firestore.models import Device
from adapters.db.firestore.base import OperationResult, QueryOptions


@pytest.mark.unit
class TestServerDevicesStore:
    @pytest.fixture
    def mock_client(self):
        client = Mock()
        collection = Mock()
        # Chainable query methods
        collection.where.return_value = collection
        collection.order_by.return_value = collection
        collection.limit.return_value = collection
        client.collection.return_value = collection
        return client

    @pytest.fixture
    def store(self, mock_client):
        return DevicesStore(mock_client)

    @pytest.fixture
    def sample_device(self):
        return Device(
            tenant_id="tenant-123",
            device_id="device-abc",
            metadata={"location": "lab"},
            status="active",
        )

    # create
    def test_create_success(self, store, sample_device):
        doc_ref = Mock()
        store.collection.document.return_value = doc_ref

        result = store.create(sample_device)

        assert result.success is True
        assert result.data == "tenant-123_device-abc"
        doc_ref.set.assert_called_once()

    def test_create_permission_denied(self, store, sample_device):
        doc_ref = Mock()
        doc_ref.set.side_effect = PermissionDenied("denied")
        store.collection.document.return_value = doc_ref

        result = store.create(sample_device)
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_create_exception(self, store, sample_device):
        doc_ref = Mock()
        doc_ref.set.side_effect = Exception("boom")
        store.collection.document.return_value = doc_ref

        result = store.create(sample_device)
        assert result.success is False
        assert result.error_code == "CREATE_FAILED"

    # get_by_id
    def test_get_by_id_success(self, store):
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.id = "tenant-123_device-abc"
        mock_doc.to_dict.return_value = {
            "tenant_id": "tenant-123",
            "device_id": "device-abc",
            "metadata": {},
            "status": "active",
            "last_seen": int(time.time() * 1000),
        }
        store.collection.document.return_value.get.return_value = mock_doc

        result = store.get_by_id("tenant-123_device-abc")
        assert result.success is True
        assert isinstance(result.data, Device)
        assert result.data.id == "tenant-123_device-abc"

    def test_get_by_id_not_found(self, store):
        mock_doc = Mock()
        mock_doc.exists = False
        store.collection.document.return_value.get.return_value = mock_doc

        result = store.get_by_id("missing")
        assert result.success is False
        assert result.error == "Device not found"

    def test_get_by_id_permission_denied(self, store):
        store.collection.document.return_value.get.side_effect = PermissionDenied("denied")
        result = store.get_by_id("id")
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_get_by_id_exception(self, store):
        store.collection.document.return_value.get.side_effect = Exception("err")
        result = store.get_by_id("id")
        assert result.success is False
        assert result.error_code == "GET_FAILED"

    # update
    def test_update_success(self, store):
        doc_ref = store.collection.document.return_value
        # get_by_id result after update
        device = Device(tenant_id="tenant-123", device_id="device-abc")
        with patch.object(store, "get_by_id", return_value=OperationResult(success=True, data=device)):
            result = store.update("tenant-123_device-abc", {"status": "inactive"})
        # ensure updated_at added
        kwargs = doc_ref.update.call_args[0][0]
        assert "updated_at" in kwargs
        assert result.success is True

    def test_update_permission_denied(self, store):
        store.collection.document.return_value.update.side_effect = PermissionDenied("denied")
        result = store.update("id", {"status": "inactive"})
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_update_exception(self, store):
        store.collection.document.return_value.update.side_effect = Exception("err")
        result = store.update("id", {"status": "inactive"})
        assert result.success is False
        assert result.error_code == "UPDATE_FAILED"

    # delete
    def test_delete_success(self, store):
        with patch.object(store, "get_by_id", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))):
            result = store.delete("t_d")
        assert result.success is True
        store.collection.document.return_value.delete.assert_called_once()

    def test_delete_not_found(self, store):
        with patch.object(store, "get_by_id", return_value=OperationResult(success=False, error="Device not found")):
            result = store.delete("missing")
        assert result.success is False
        assert result.error_code == "NOT_FOUND"

    def test_delete_permission_denied(self, store):
        with patch.object(store, "get_by_id", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))):
            store.collection.document.return_value.delete.side_effect = PermissionDenied("denied")
            result = store.delete("t_d")
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_delete_exception(self, store):
        with patch.object(store, "get_by_id", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))):
            store.collection.document.return_value.delete.side_effect = Exception("err")
            result = store.delete("t_d")
        assert result.success is False
        assert result.error_code == "DELETE_FAILED"

    # wrappers
    def test_get_device_success(self, store):
        with patch.object(store, "get_by_id", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))):
            result = store.get_device("t", "d")
        assert result.success is True

    def test_get_device_exception(self, store):
        with patch.object(store, "get_by_id", side_effect=Exception("err")):
            result = store.get_device("t", "d")
        assert result.success is False
        assert result.error_code == "GET_FAILED"

    def test_update_device_metadata_success(self, store):
        with patch.object(store, "update", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))):
            result = store.update_device_metadata("t", "d", {"k": "v"})
        assert result.success is True

    def test_update_device_metadata_exception(self, store):
        with patch.object(store, "update", side_effect=Exception("err")):
            result = store.update_device_metadata("t", "d", {"k": "v"})
        assert result.success is False
        assert result.error_code == "UPDATE_FAILED"

    def test_update_last_seen_success(self, store):
        with patch("time.time", return_value=1234.5):
            with patch.object(store, "update", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))) as upd:
                result = store.update_last_seen("t", "d")
        assert result.success is True
        upd.assert_called_once()
        # 1234.5s -> 1234500 ms
        assert upd.call_args[0][1]["last_seen"] == 1234500

    def test_update_last_seen_exception(self, store):
        with patch.object(store, "update", side_effect=Exception("err")):
            result = store.update_last_seen("t", "d")
        assert result.success is False
        assert result.error_code == "UPDATE_FAILED"

    def test_set_status_success(self, store):
        with patch.object(store, "update", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))):
            result = store.set_status("t", "d", "inactive")
        assert result.success is True

    def test_set_status_exception(self, store):
        with patch.object(store, "update", side_effect=Exception("err")):
            result = store.set_status("t", "d", "inactive")
        assert result.success is False
        assert result.error_code == "UPDATE_FAILED"

    def test_delete_device_success(self, store):
        with patch.object(store, "delete", return_value=OperationResult(success=True, data=True)):
            result = store.delete_device("t", "d")
        assert result.success is True

    def test_delete_device_exception(self, store):
        with patch.object(store, "delete", side_effect=Exception("err")):
            result = store.delete_device("t", "d")
        assert result.success is False
        assert result.error_code == "DELETE_FAILED"

    # list_for_tenant and queries
    def _make_doc(self, data, id_="doc1"):
        doc = Mock()
        doc.id = id_
        doc.to_dict.return_value = data
        return doc

    def test_list_for_tenant_success(self, store):
        now_ms = int(time.time() * 1000)
        store.collection.stream.return_value = [
            self._make_doc({"tenant_id": "t", "device_id": "d1", "last_seen": now_ms, "status": "active"}, id_="t_d1"),
            self._make_doc({"tenant_id": "t", "device_id": "d2", "last_seen": now_ms, "status": "inactive"}, id_="t_d2"),
        ]
        result = store.list_for_tenant("t")
        assert result.success is True
        assert len(result.data.items) == 2
        assert all(isinstance(it, Device) for it in result.data.items)

    def test_list_for_tenant_permission_denied(self, store):
        store.collection.stream.side_effect = PermissionDenied("denied")
        result = store.list_for_tenant("t")
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_list_for_tenant_exception(self, store):
        store.collection.stream.side_effect = Exception("err")
        result = store.list_for_tenant("t")
        assert result.success is False
        assert result.error_code == "LIST_FAILED"

    def test_get_by_status_success_and_has_more(self, store):
        now_ms = int(time.time() * 1000)
        store.collection.stream.return_value = [
            self._make_doc({"tenant_id": "t", "device_id": "d1", "last_seen": now_ms, "status": "active"}, id_="t_d1"),
        ]
        result = store.get_by_status("t", "active", options=QueryOptions(limit=1))
        assert result.success is True
        assert len(result.data.items) == 1
        assert result.data.has_more is True
        assert result.data.next_offset == "t_d1"

    def test_get_by_status_permission_denied(self, store):
        store.collection.stream.side_effect = PermissionDenied("denied")
        result = store.get_by_status("t", "active")
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_get_by_status_exception(self, store):
        store.collection.stream.side_effect = Exception("err")
        result = store.get_by_status("t", "active")
        assert result.success is False
        assert result.error_code == "QUERY_FAILED"

    def test_get_inactive_devices_success(self, store):
        old_ms = int((time.time() - 7200) * 1000)
        store.collection.stream.return_value = [
            self._make_doc({"tenant_id": "t", "device_id": "d1", "last_seen": old_ms, "status": "active"}, id_="t_d1"),
        ]
        result = store.get_inactive_devices("t", inactive_threshold_ms=3600000)
        assert result.success is True
        assert len(result.data.items) == 1

    def test_get_inactive_devices_permission_denied(self, store):
        store.collection.stream.side_effect = PermissionDenied("denied")
        result = store.get_inactive_devices("t")
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_get_inactive_devices_exception(self, store):
        store.collection.stream.side_effect = Exception("err")
        result = store.get_inactive_devices("t")
        assert result.success is False
        assert result.error_code == "QUERY_FAILED"

    # check_exists and count
    def test_check_exists_true(self, store):
        with patch.object(store, "get_device", return_value=OperationResult(success=True, data=Device(tenant_id="t", device_id="d"))):
            result = store.check_exists("t", "d")
        assert result.success is True
        assert result.data is True

    def test_check_exists_false(self, store):
        with patch.object(store, "get_device", return_value=OperationResult(success=False, error="Device not found")):
            result = store.check_exists("t", "d")
        assert result.success is True
        assert result.data is False

    def test_get_device_count_success(self, store):
        # stream returns three docs
        q = store.collection.where.return_value
        q.stream.return_value = [Mock(), Mock(), Mock()]
        result = store.get_device_count("t")
        assert result.success is True
        assert result.data == 3

    def test_get_device_count_permission_denied(self, store):
        q = store.collection.where.return_value
        q.stream.side_effect = PermissionDenied("denied")
        result = store.get_device_count("t")
        assert result.success is False
        assert result.error_code == "PERMISSION_DENIED"

    def test_get_device_count_exception(self, store):
        q = store.collection.where.return_value
        q.stream.side_effect = Exception("err")
        result = store.get_device_count("t")
        assert result.success is False
        assert result.error_code == "COUNT_FAILED"

    # internal helper
    def test_add_update_timestamp(self, store):
        result = store._add_update_timestamp({"a": 1})
        assert "updated_at" in result and isinstance(result["updated_at"], int)


