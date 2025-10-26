"""Firestore client factory and configuration."""

import os
import logging
from typing import Optional
from google.cloud import firestore
from google.auth import default

logger = logging.getLogger(__name__)


class FirestoreClientFactory:
    """Factory for creating Firestore clients with proper configuration."""
    
    @staticmethod
    def create_client(project_id: Optional[str] = None, emulator_host: Optional[str] = None) -> firestore.Client:
        """
        Create a Firestore client with appropriate configuration.
        
        Args:
            project_id: GCP project ID. If None, will attempt to get from environment or ADC.
            emulator_host: Emulator host if running locally (e.g., "127.0.0.1:8080")
            
        Returns:
            Configured Firestore client
        """
        try:
            client = None
            # Check if we should use emulator
            use_emulators = os.getenv('USE_EMULATORS', '0') in {'1', 'true', 'True'}
            if emulator_host or (use_emulators and os.getenv('FIRESTORE_EMULATOR_HOST')):
                logger.info(f"Using Firestore emulator at {emulator_host}")
                os.environ['FIRESTORE_EMULATOR_HOST'] = emulator_host or os.getenv('FIRESTORE_EMULATOR_HOST')
                
                # For emulator, we can use a dummy project ID
                client_project_id = project_id or os.getenv('GOOGLE_CLOUD_PROJECT') or 'local-dev'
                client = firestore.Client(project=client_project_id)
                logger.info(f"Firestore emulator client created for project: {client_project_id}")
            
            # Use production Firestore
            # Ensure emulator env var is not set when using production
            if client is None and 'FIRESTORE_EMULATOR_HOST' in os.environ:
                logger.info("Unsetting FIRESTORE_EMULATOR_HOST for production client")
                del os.environ['FIRESTORE_EMULATOR_HOST']

            if client is None:
                if project_id:
                    logger.info(f"Creating Firestore client for project: {project_id}")
                    client = firestore.Client(project=project_id)
                else:
                    # Try to get project ID from environment or ADC
                    try:
                        credentials, project_id = default()
                        logger.info(f"Using ADC credentials for project: {project_id}")
                        client = firestore.Client(project=project_id, credentials=credentials)
                    except Exception as e:
                        logger.warning(f"Failed to get project ID from ADC: {e}")
                        # Fallback to default client
                        client = firestore.Client()
                        logger.info("Created Firestore client with default configuration")
            
            logger.info("Firestore client created successfully")
            return client
            
        except Exception as e:
            logger.error(f"Failed to create Firestore client: {e}")
            raise


def get_firestore_client(config) -> Optional[firestore.Client]:
    """
    Get a configured Firestore client based on configuration.
    
    Args:
        config: AuthConfig instance with Firestore settings
        
    Returns:
        Firestore client or None if not configured
    """
    try:
        result_client: Optional[firestore.Client] = None
        # If config looks like a mock (common in tests), skip real client init
        try:
            is_mock_config = type(config).__name__ == 'Mock' or getattr(config, '_is_mock', False)
        except Exception:
            is_mock_config = False

        # Check if Firestore is enabled for any feature
        enabled = any([
            getattr(config, 'use_firestore_telemetry', False),
            getattr(config, 'use_firestore_auth', False), 
            getattr(config, 'use_firestore_audit', False)
        ])
        if enabled:
            # Prefer explicit config, but allow ADC fallback when project ID isn't provided
            # In unit tests some configs are Mock but still expect client creation via patching;
            # don't early return here, allow patched create_client to be called.
            result_client = FirestoreClientFactory.create_client(
                project_id=getattr(config, 'gcp_project_id', None),
                emulator_host=getattr(config, 'firestore_emulator_host', None)
            )
            logger.info("Firestore client initialized successfully")
        else:
            logger.debug("Firestore features not enabled")

        return result_client

    except Exception as e:
        logger.error(f"Failed to initialize Firestore client: {e}")
        return None
