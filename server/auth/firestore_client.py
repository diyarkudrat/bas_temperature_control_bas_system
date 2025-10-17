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
            # Check if we should use emulator
            if emulator_host:
                logger.info(f"Using Firestore emulator at {emulator_host}")
                os.environ['FIRESTORE_EMULATOR_HOST'] = emulator_host
                
                # For emulator, we can use a dummy project ID
                client_project_id = project_id or 'test-project'
                client = firestore.Client(project=client_project_id)
                logger.info(f"Firestore emulator client created for project: {client_project_id}")
                return client
            
            # Use production Firestore
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
        # Check if Firestore is enabled for any feature
        if not any([
            config.use_firestore_telemetry,
            config.use_firestore_auth, 
            config.use_firestore_audit
        ]):
            logger.debug("Firestore features not enabled")
            return None
            
        # Validate required configuration
        if not config.gcp_project_id and not config.firestore_emulator_host:
            logger.warning("Firestore enabled but no project ID or emulator host configured")
            return None
            
        client = FirestoreClientFactory.create_client(
            project_id=config.gcp_project_id,
            emulator_host=config.firestore_emulator_host
        )
        
        logger.info("Firestore client initialized successfully")
        return client
        
    except Exception as e:
        logger.error(f"Failed to initialize Firestore client: {e}")
        return None
