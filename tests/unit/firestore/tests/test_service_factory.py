"""Tests for the real FirestoreServiceFactory implementation with full branch coverage."""

import pytest
from unittest.mock import Mock, patch

from adapters.db.firestore.base import FirestoreError
from adapters.db.firestore.service_factory import (
    FirestoreServiceFactory,
    get_service_factory,
    reset_service_factory,
)

from tests.contracts.firestore import ContractValidator
from tests.utils.business_rules import BusinessRules
from tests.utils.assertions import (
    assert_equals,
    assert_not_equals,
    assert_true,
    assert_false,
    assert_is_not_none,
    assert_is_instance,
)


class SimpleConfig:
    def __init__(self, use_firestore_auth=True, use_firestore_audit=True):
        self.use_firestore_auth = use_firestore_auth
        self.use_firestore_audit = use_firestore_audit


@pytest.mark.auth
@pytest.mark.unit
class TestFirestoreServiceFactory:
    @pytest.fixture
    def mock_client(self):
        client = Mock(spec_set=['collections', 'collection'])
        client.collections.return_value = iter(())
        # Repositories call client.collection(<name>) during construction
        client.collection.return_value = Mock()
        return client

    @pytest.fixture
    def factory_with_client(self, mock_client):
        return FirestoreServiceFactory(mock_client)

    @pytest.fixture
    def simple_config(self):
        return SimpleConfig()

    def test_init_with_client_sets_cache_and_config(self, mock_client):
        factory = FirestoreServiceFactory(mock_client)
        assert_equals(factory.client, mock_client, "Client should be set from ctor")
        assert_equals(factory._repositories, {}, "Repositories cache should start empty")

    def test_init_with_config_delays_client_creation(self, simple_config):
        factory = FirestoreServiceFactory(simple_config)
        assert_is_not_none(factory.config, "Config should be stored")
        # client created lazily
        with patch('adapters.db.firestore.service_factory.get_firestore_client', return_value=Mock()) as p:
            _ = factory.client
            assert_true(p.called, "Client should be created lazily from config")

    def test_client_property_returns_existing_client(self, factory_with_client, mock_client):
        assert_equals(factory_with_client.client, mock_client, "Should return provided client")
        assert_equals(factory_with_client.client, mock_client, "Should be cached")

    def test_client_property_creates_from_config_when_available(self):
        config = SimpleConfig()
        fake_client = Mock()
        factory = FirestoreServiceFactory(config)
        with patch('adapters.db.firestore.service_factory.get_firestore_client', return_value=fake_client):
            assert_equals(factory.client, fake_client, "Should use client returned by factory")

    def test_client_property_uses_noop_when_config_is_mock_and_factory_returns_none(self):
        mock_config = Mock()
        mock_config.use_firestore_auth = True
        mock_config.use_firestore_audit = True
        factory = FirestoreServiceFactory(mock_config)
        with patch('adapters.db.firestore.service_factory.get_firestore_client', return_value=None):
            client = factory.client
            # Noop client exposes collections() -> iterator
            assert_true(hasattr(client, 'collections'))
            it = client.collections()
            assert_equals(next(it, None), None, "Noop collections should be empty")

    def test_client_property_raises_when_no_client_and_non_mock_config(self):
        config = SimpleConfig()
        factory = FirestoreServiceFactory(config)
        with patch('adapters.db.firestore.service_factory.get_firestore_client', return_value=None):
            with pytest.raises(FirestoreError):
                _ = factory.client

    def test_repository_methods_create_and_cache(self, factory_with_client):
        u1 = factory_with_client.get_users_service()
        u2 = factory_with_client.get_users_service()
        assert_equals(u1, u2, "Users should be cached")

        s1 = factory_with_client.get_sessions_service()
        s2 = factory_with_client.get_sessions_service()
        assert_equals(s1, s2, "Sessions should be cached")

        a1 = factory_with_client.get_audit_service()
        a2 = factory_with_client.get_audit_service()
        assert_equals(a1, a2, "Audit should be cached")

        d1 = factory_with_client.get_devices_service()
        d2 = factory_with_client.get_devices_service()
        assert_equals(d1, d2, "Devices should be cached")

    def test_get_all_repositories_includes_all(self, factory_with_client):
        repos = factory_with_client.get_all_repositories()
        assert_equals(set(repos.keys()), {"users", "sessions", "audit", "devices", "tenants", "members", "invites", "idempotency", "outbox"})

    def test_reset_repositories_clears_cache_but_keeps_client(self, factory_with_client):
        _ = factory_with_client.get_users_service()
        _ = factory_with_client.get_devices_service()
        assert_true(len(factory_with_client._repositories) >= 2)
        factory_with_client.reset_repositories()
        assert_equals(len(factory_with_client._repositories), 0)
        assert_is_not_none(factory_with_client.client)

    def test_feature_flags_reflect_config(self):
        cfg = SimpleConfig(use_firestore_auth=True, use_firestore_audit=False)
        factory = FirestoreServiceFactory(cfg)
        # Patch client creation to avoid real init
        with patch('adapters.db.firestore.service_factory.get_firestore_client', return_value=Mock()):
            _ = factory.client
        assert_true(factory.is_auth_enabled())
        assert_false(factory.is_audit_enabled())

    def test_health_check_healthy(self, mock_client):
        factory = FirestoreServiceFactory(mock_client)
        result = factory.health_check()
        assert_equals(result['status'], 'healthy')
        assert_true(result['client_initialized'])
        assert_true(result['services']['auth'])
        assert_true(result['services']['audit'])

    def test_health_check_unhealthy_on_exception(self):
        bad_client = Mock(spec_set=['collections'])
        bad_client.collections.side_effect = Exception("boom")
        factory = FirestoreServiceFactory(bad_client)
        result = factory.health_check()
        assert_equals(result['status'], 'unhealthy')
        assert_false(result['client_initialized'])


@pytest.mark.auth
@pytest.mark.unit
class TestGlobalServiceFactory:
    @pytest.fixture
    def mock_client(self):
        client = Mock(spec_set=['collections', 'collection'])
        client.collections.return_value = iter(())
        client.collection.return_value = Mock()
        return client

    def test_get_service_factory_creates_new(self, mock_client):
        reset_service_factory()
        factory = get_service_factory(mock_client)
        assert_is_instance(factory, FirestoreServiceFactory)
        assert_equals(factory.client, mock_client)

    def test_get_service_factory_returns_existing(self, mock_client):
        reset_service_factory()
        f1 = get_service_factory(mock_client)
        f2 = get_service_factory(mock_client)
        assert_equals(f1, f2)

    def test_reset_service_factory_creates_new_instance(self, mock_client):
        reset_service_factory()
        f1 = get_service_factory(mock_client)
        reset_service_factory()
        f2 = get_service_factory(mock_client)
        assert_not_equals(f1, f2)

    def test_get_service_factory_with_different_clients(self):
        reset_service_factory()
        c1 = Mock(spec_set=['collections', 'collection']); c1.collections.return_value = iter(());
        c1.collection.return_value = Mock()
        c2 = Mock(spec_set=['collections', 'collection']); c2.collections.return_value = iter(());
        c2.collection.return_value = Mock()
        f1 = get_service_factory(c1)
        reset_service_factory()
        f2 = get_service_factory(c2)
        assert_equals(f1.client, c1)
        assert_equals(f2.client, c2)
