"""Firestore client factory and configuration (migrated)."""

import logging
import os
from typing import Optional

from google.auth import default
from google.cloud import firestore


logger = logging.getLogger(__name__)


class FirestoreClientFactory:
    """Firestore client factory."""

    @staticmethod
    def create_client(project_id: Optional[str] = None, emulator_host: Optional[str] = None) -> firestore.Client:
        """Create a Firestore client."""

        try:
            client = None
            use_emulators = os.getenv('USE_EMULATORS', '0') in {'1', 'true', 'True'}

            if emulator_host or (use_emulators and os.getenv('FIRESTORE_EMULATOR_HOST')):
                logger.info(f"Using Firestore emulator at {emulator_host}")

                os.environ['FIRESTORE_EMULATOR_HOST'] = emulator_host or os.getenv('FIRESTORE_EMULATOR_HOST')
                client_project_id = project_id or os.getenv('GOOGLE_CLOUD_PROJECT') or 'local-dev'
                client = firestore.Client(project=client_project_id)

                logger.info(f"Firestore emulator client created for project: {client_project_id}")

            if client is None and 'FIRESTORE_EMULATOR_HOST' in os.environ:
                logger.info("Unsetting FIRESTORE_EMULATOR_HOST for production client")

                del os.environ['FIRESTORE_EMULATOR_HOST']

            if client is None:
                if project_id:
                    logger.info(f"Creating Firestore client for project: {project_id}")

                    client = firestore.Client(project=project_id)
                else:
                    try:
                        credentials, project_id = default()
                        logger.info(f"Using ADC credentials for project: {project_id}")

                        client = firestore.Client(project=project_id, credentials=credentials)
                    except Exception as e:
                        logger.warning(f"Failed to get project ID from ADC: {e}")
                        client = firestore.Client()

                        logger.info("Created Firestore client with default configuration")

            logger.info("Firestore client created successfully")
            
            return client
        except Exception as e:
            logger.error(f"Failed to create Firestore client: {e}")
            raise


def get_firestore_client(config) -> Optional[firestore.Client]:
    """Get a Firestore client."""

    try:
        result_client: Optional[firestore.Client] = None

        # Check if the config is a mock
        try:
            is_mock_config = type(config).__name__ == 'Mock' or getattr(config, '_is_mock', False)
        except Exception:
            is_mock_config = False

        enabled = any([
            getattr(config, 'use_firestore_auth', False),
            getattr(config, 'use_firestore_audit', False),
        ])

        if enabled:
            result_client = FirestoreClientFactory.create_client(
                project_id=getattr(config, 'gcp_project_id', None),
                emulator_host=getattr(config, 'firestore_emulator_host', None),
            )

            logger.info("Firestore client initialized successfully")
        else:
            logger.debug("Firestore features not enabled")

        return result_client
    except Exception as e:
        logger.error(f"Failed to initialize Firestore client: {e}")

        return None