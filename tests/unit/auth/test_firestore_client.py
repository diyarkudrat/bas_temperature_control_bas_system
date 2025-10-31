"""Tests for Firestore Client Factory."""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock
from google.cloud import firestore
from google.auth import default

from adapters.db.firestore.client import FirestoreClientFactory, get_firestore_client
from tests.utils.assertions import assert_equals, assert_not_equals, assert_true, assert_false, assert_is_none, assert_is_not_none, assert_is_instance, assert_raises


@pytest.mark.auth
@pytest.mark.unit
class TestFirestoreClientFactory:
    """Test cases for FirestoreClientFactory."""
    
    def test_create_client_unsets_emulator_env_for_production(self):
        """Ensure production client creation unsets emulator env var if present."""
        original_env = os.environ.get('FIRESTORE_EMULATOR_HOST')
        os.environ['FIRESTORE_EMULATOR_HOST'] = 'localhost:9999'
        try:
            with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                result = FirestoreClientFactory.create_client(project_id="prod-project")

                # Env var should be removed for production clients
                assert_true('FIRESTORE_EMULATOR_HOST' not in os.environ, "Should unset emulator host env var for production")
                mock_client_class.assert_called_once_with(project="prod-project")
                assert_equals(result, mock_client, "Should return created client")
        finally:
            if original_env is None:
                if 'FIRESTORE_EMULATOR_HOST' in os.environ:
                    del os.environ['FIRESTORE_EMULATOR_HOST']
            else:
                os.environ['FIRESTORE_EMULATOR_HOST'] = original_env

    def test_create_client_with_emulator_host(self):
        """Test creating client with emulator host."""
        emulator_host = "127.0.0.1:8080"
        project_id = "test-project"
        
        with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            result = FirestoreClientFactory.create_client(
                project_id=project_id,
                emulator_host=emulator_host
            )
            
            # Verify environment variable was set
            assert_equals(os.environ.get('FIRESTORE_EMULATOR_HOST'), emulator_host, "Should set emulator host env var")
            
            # Verify client was created with correct project
            mock_client_class.assert_called_once_with(project=project_id)
            assert_equals(result, mock_client, "Should return created client")
    
    def test_create_client_with_emulator_host_no_project_id(self):
        """Test creating client with emulator host but no project ID."""
        emulator_host = "127.0.0.1:8080"
        
        with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            result = FirestoreClientFactory.create_client(emulator_host=emulator_host)
            
            # Verify environment variable was set
            assert_equals(os.environ.get('FIRESTORE_EMULATOR_HOST'), emulator_host, "Should set emulator host env var")
            
            # Verify client was created with default project ID
            mock_client_class.assert_called_once_with(project='test-project')
            assert_equals(result, mock_client, "Should return created client")
    
    def test_create_client_with_project_id_no_emulator(self):
        """Test creating client with project ID but no emulator."""
        project_id = "production-project"
        
        with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            result = FirestoreClientFactory.create_client(project_id=project_id)
            
            # Verify emulator host env var was not set
            assert_true('FIRESTORE_EMULATOR_HOST' not in os.environ, "Should not set emulator host env var")
            
            # Verify client was created with correct project
            mock_client_class.assert_called_once_with(project=project_id)
            assert_equals(result, mock_client, "Should return created client")
    
    def test_create_client_with_adc_credentials(self):
        """Test creating client using Application Default Credentials."""
        with patch('adapters.db.firestore.client.default') as mock_default:
            with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
                # Mock ADC credentials
                mock_credentials = Mock()
                mock_project_id = "adc-project"
                mock_default.return_value = (mock_credentials, mock_project_id)
                
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                
                result = FirestoreClientFactory.create_client()
                
                # Verify ADC was called
                mock_default.assert_called_once()
                
                # Verify client was created with ADC credentials and project
                mock_client_class.assert_called_once_with(project=mock_project_id, credentials=mock_credentials)
                assert_equals(result, mock_client, "Should return created client")
    
    def test_create_client_adc_fallback(self):
        """Test creating client with ADC fallback to default client."""
        with patch('adapters.db.firestore.client.default') as mock_default:
            with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
                # Mock ADC failure
                mock_default.side_effect = Exception("ADC failed")
                
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                
                result = FirestoreClientFactory.create_client()
                
                # Verify ADC was attempted
                mock_default.assert_called_once()
                
                # Verify fallback to default client
                mock_client_class.assert_called_once_with()
                assert_equals(result, mock_client, "Should return created client")
    
    def test_create_client_exception_handling(self):
        """Test exception handling in client creation."""
        with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
            mock_client_class.side_effect = Exception("Client creation failed")
            
            with assert_raises(Exception) as exc_info:
                FirestoreClientFactory.create_client(project_id="test-project")
            
            assert_equals(str(exc_info.value), "Client creation failed", "Should propagate exception")
    
    def test_create_client_environment_cleanup(self):
        """Test that environment variables are properly handled."""
        original_env = os.environ.get('FIRESTORE_EMULATOR_HOST')
        
        try:
            emulator_host = "127.0.0.1:8080"
            
            with patch('adapters.db.firestore.client.firestore.Client') as mock_client_class:
                mock_client = Mock()
                mock_client_class.return_value = mock_client
                
                FirestoreClientFactory.create_client(emulator_host=emulator_host)
                
                # Verify environment variable was set
                assert_equals(os.environ.get('FIRESTORE_EMULATOR_HOST'), emulator_host, "Should set emulator host")
        
        finally:
            # Clean up environment
            if original_env is None:
                if 'FIRESTORE_EMULATOR_HOST' in os.environ:
                    del os.environ['FIRESTORE_EMULATOR_HOST']
            else:
                os.environ['FIRESTORE_EMULATOR_HOST'] = original_env


@pytest.mark.auth
@pytest.mark.unit
class TestGetFirestoreClient:
    """Test cases for get_firestore_client function."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock config for testing."""
        config = Mock()
        config.use_firestore_auth = False
        config.use_firestore_audit = False
        config.gcp_project_id = None
        config.firestore_emulator_host = None
        return config
    
    def test_get_firestore_client_no_features_enabled(self, mock_config):
        """Test get_firestore_client when no features are enabled."""
        result = get_firestore_client(mock_config)
        
        assert_is_none(result, "Should return None when no features enabled")
    
    def test_get_firestore_client_auth_enabled(self, mock_config):
        """Test get_firestore_client when auth is enabled."""
        mock_config.use_firestore_auth = True
        mock_config.gcp_project_id = "test-project"
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_client = Mock()
            mock_create.return_value = mock_client
            
            result = get_firestore_client(mock_config)
            
            assert_equals(result, mock_client, "Should return client when auth enabled")
            mock_create.assert_called_once_with(
                project_id="test-project",
                emulator_host=None
            )
    
    def test_get_firestore_client_audit_enabled(self, mock_config):
        """Test get_firestore_client when audit is enabled."""
        mock_config.use_firestore_audit = True
        mock_config.gcp_project_id = "test-project"
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_client = Mock()
            mock_create.return_value = mock_client
            
            result = get_firestore_client(mock_config)
            
            assert_equals(result, mock_client, "Should return client when audit enabled")
            mock_create.assert_called_once_with(
                project_id="test-project",
                emulator_host=None
            )
    
    def test_get_firestore_client_multiple_features_enabled(self, mock_config):
        """Test get_firestore_client when multiple features are enabled."""
        mock_config.use_firestore_auth = True
        mock_config.use_firestore_audit = True
        mock_config.gcp_project_id = "test-project"
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_client = Mock()
            mock_create.return_value = mock_client
            
            result = get_firestore_client(mock_config)
            
            assert_equals(result, mock_client, "Should return client when multiple features enabled")
            mock_create.assert_called_once_with(
                project_id="test-project",
                emulator_host=None
            )
    
    def test_get_firestore_client_with_emulator_host(self, mock_config):
        """Test get_firestore_client with emulator host."""
        mock_config.use_firestore_auth = True
        mock_config.firestore_emulator_host = "127.0.0.1:8080"
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_client = Mock()
            mock_create.return_value = mock_client
            
            result = get_firestore_client(mock_config)
            
            assert_equals(result, mock_client, "Should return client when emulator host provided")
            mock_create.assert_called_once_with(
                project_id=None,
                emulator_host="127.0.0.1:8080"
            )
    
    def test_get_firestore_client_no_config(self, mock_config):
        """Test get_firestore_client with no project ID or emulator host."""
        mock_config.use_firestore_auth = True
        # gcp_project_id and firestore_emulator_host are None by default
        
        result = get_firestore_client(mock_config)
        
        assert_is_none(result, "Should return None when no project ID or emulator host")
    
    def test_get_firestore_client_factory_exception(self, mock_config):
        """Test get_firestore_client when factory raises exception."""
        mock_config.use_firestore_auth = True
        mock_config.gcp_project_id = "test-project"
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_create.side_effect = Exception("Factory failed")
            
            result = get_firestore_client(mock_config)
            
            assert_is_none(result, "Should return None when factory fails")
    
    def test_get_firestore_client_validation_priority(self, mock_config):
        """Test that get_firestore_client validates configuration properly."""
        # Test with features enabled but no project ID or emulator
        mock_config.use_firestore_auth = True
        
        result = get_firestore_client(mock_config)
        
        assert_is_none(result, "Should return None when features enabled but no config")
        
        # Test with project ID but no features enabled
        mock_config.use_firestore_auth = False
        mock_config.gcp_project_id = "test-project"
        
        result = get_firestore_client(mock_config)
        
        assert_is_none(result, "Should return None when no features enabled")
    
    def test_get_firestore_client_emulator_priority(self, mock_config):
        """Test that emulator host takes priority over project ID."""
        mock_config.use_firestore_auth = True
        mock_config.gcp_project_id = "production-project"
        mock_config.firestore_emulator_host = "127.0.0.1:8080"
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_client = Mock()
            mock_create.return_value = mock_client
            
            result = get_firestore_client(mock_config)
            
            # Should use emulator host, not project ID
            mock_create.assert_called_once_with(
                project_id="production-project",
                emulator_host="127.0.0.1:8080"
            )
            assert_equals(result, mock_client, "Should return client")
    
    def test_get_firestore_client_config_attributes(self, mock_config):
        """Test that get_firestore_client accesses correct config attributes."""
        mock_config.use_firestore_auth = True
        mock_config.use_firestore_audit = False
        mock_config.gcp_project_id = "test-project"
        mock_config.firestore_emulator_host = None
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_client = Mock()
            mock_create.return_value = mock_client
            
            get_firestore_client(mock_config)
            
            # Verify all config attributes were accessed
            assert_true(hasattr(mock_config, 'use_firestore_auth'), "Should check auth flag")
            assert_true(hasattr(mock_config, 'use_firestore_audit'), "Should check audit flag")
            assert_true(hasattr(mock_config, 'gcp_project_id'), "Should check project ID")
            assert_true(hasattr(mock_config, 'firestore_emulator_host'), "Should check emulator host")
    
    def test_get_firestore_client_real_config_object(self):
        """Test get_firestore_client with real config object."""
        from app_platform.config.auth import AuthConfig
        
        config = AuthConfig()
        config.use_firestore_auth = True
        config.gcp_project_id = "test-project"
        
        with patch('adapters.db.firestore.client.FirestoreClientFactory.create_client') as mock_create:
            mock_client = Mock()
            mock_create.return_value = mock_client
            
            result = get_firestore_client(config)
            
            assert_equals(result, mock_client, "Should work with real AuthConfig object")
            mock_create.assert_called_once_with(
                project_id="test-project",
                emulator_host=None
            )

    def test_get_firestore_client_handles_is_mock_attr_exception(self):
        """Ensure getattr exception for _is_mock is handled and function proceeds."""
        class WeirdConfig:
            def __init__(self):
                self.use_firestore_auth = False
                self.use_firestore_audit = False
                self.gcp_project_id = None
                self.firestore_emulator_host = None

            def __getattribute__(self, name):
                if name == '_is_mock':
                    raise RuntimeError('boom')
                return object.__getattribute__(self, name)

        cfg = WeirdConfig()
        result = get_firestore_client(cfg)
        assert_is_none(result, "Should return None even if _is_mock getattr raises")
