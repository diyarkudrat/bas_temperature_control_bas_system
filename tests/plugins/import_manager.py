"""Pytest plugin for managing imports and Python path configuration."""

import os
import sys
import pytest
from pytest import hookimpl
import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


def pytest_configure(config):
    """Configure pytest with import path management."""
    # Register import-related markers
    config.addinivalue_line(
        "markers", "import_test: Tests that validate import functionality"
    )

    # Setup import paths without sys.path mutations
    _setup_import_paths()

    logger.info("Import manager configured: Python paths set up for testing")

    # Normalize internal bestrelpath to guard against accidental leading '//'
    try:
        import _pytest.pathlib as pyl
        import _pytest.main as pymain
        import _pytest._code.code as pycode
        from _pytest.main import Session as _Session

        _orig_bestrelpath_pathlib = getattr(pyl, "bestrelpath", None)
        _orig_bestrelpath_main = getattr(pymain, "bestrelpath", None)
        _orig_node_loc_to_rel = getattr(_Session, "_node_location_to_relpath", None)

        def _normalize_leading_slashes(p: Path | str) -> Path:
            try:
                s = str(p)
                if s.startswith("//"):
                    return Path("/" + s.lstrip("/"))
                return Path(s)
            except Exception:
                return Path(p)

        def _wrap_bestrelpath(orig):
            if not callable(orig):
                return None

            def _wrapped(base, dest):
                base_n = _normalize_leading_slashes(base)
                dest_n = _normalize_leading_slashes(dest)
                try:
                    return orig(base_n, dest_n)
                except Exception:
                    try:
                        from os.path import relpath
                        return relpath(str(dest_n), str(base_n))
                    except Exception:
                        return str(dest_n)

            return _wrapped

        wrapped_pathlib = _wrap_bestrelpath(_orig_bestrelpath_pathlib)
        if wrapped_pathlib is not None:
            pyl.bestrelpath = wrapped_pathlib  # type: ignore[attr-defined]

        wrapped_main = _wrap_bestrelpath(_orig_bestrelpath_main)
        if wrapped_main is not None:
            pymain.bestrelpath = wrapped_main  # type: ignore[attr-defined]

        # Patch any early-bound imports inside _pytest._code.code
        if hasattr(pycode, 'bestrelpath') and callable(getattr(pycode, 'bestrelpath')):
            pycode.bestrelpath = wrapped_pathlib or pycode.bestrelpath

        if callable(_orig_node_loc_to_rel):
            def _wrapped_node_loc_to_rel(self, path):
                try:
                    path_n = _normalize_leading_slashes(path)
                except Exception:
                    path_n = path
                return _orig_node_loc_to_rel(self, path_n)

            _Session._node_location_to_relpath = _wrapped_node_loc_to_rel  # type: ignore[assignment]
    except Exception:
        # Never fail configuration due to safety shim
        pass


def _setup_import_paths() -> None:
    """Set up Python import paths for testing without sys.path mutations."""
    # Get project root and key directories
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    server_path = os.path.join(project_root, 'server')
    src_path = os.path.join(project_root, 'src')
    infra_path = os.path.join(project_root, 'infra')

    # Add paths using pytest's pythonpath option instead of direct sys.path manipulation
    paths_to_add = [server_path, src_path, infra_path]

    # Only add paths that exist and aren't already in sys.path
    for path in paths_to_add:
        if os.path.exists(path) and path not in sys.path:
            sys.path.insert(0, path)
            logger.debug(f"Added to Python path: {path}")


@pytest.fixture
def import_paths():
    """Fixture providing validated import paths for testing."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    paths = {
        'project_root': project_root,
        'server': os.path.join(project_root, 'server'),
        'src': os.path.join(project_root, 'src'),
        'infra': os.path.join(project_root, 'infra'),
        'tests': os.path.join(project_root, 'tests'),
    }

    # Validate paths exist
    for name, path in paths.items():
        if not os.path.exists(path):
            pytest.fail(f"Required path {name} does not exist: {path}")

    return paths


@pytest.fixture
def validate_imports(import_paths):
    """Fixture to validate that key imports work correctly."""
    import_errors = []

    # Test critical imports
    test_imports = [
        ('adapters.db.firestore.base', 'Firestore base service'),
        ('src.bas.controller', 'BAS controller'),
        ('src.bas.services', 'BAS services'),
        ('tests.contracts.firestore', 'Contract validator'),
        ('tests.utils.business_rules', 'Business rules'),
    ]

    for module_name, description in test_imports:
        try:
            __import__(module_name)
            logger.debug(f"✓ Import successful: {module_name}")
        except ImportError as e:
            import_errors.append(f"Failed to import {description} ({module_name}): {e}")
            logger.warning(f"✗ Import failed: {module_name} - {e}")

    if import_errors:
        pytest.fail(f"Import validation failed:\n" + "\n".join(import_errors))

    return True


def pytest_collection_modifyitems(config, items):
    """Modify test collection to validate import setup."""
    # Add import_test marker to import-related tests
    for item in items:
        if 'import' in str(item.fspath).lower() or 'conftest' in str(item.fspath).lower():
            item.add_marker(pytest.mark.import_test)

    # Normalize nodeids that begin with double slashes to avoid pathlib.relative_to issues
    for item in items:
        try:
            nodeid = getattr(item, 'nodeid', None)
            if not isinstance(nodeid, str):
                continue
            path_part, sep, rest = nodeid.partition('::')
            if path_part.startswith('//'):
                normalized_path = '/' + path_part.lstrip('/')
                # item.nodeid is read-only, but _nodeid is the internal storage pytest uses
                setattr(item, '_nodeid', normalized_path + (sep + rest if sep else ''))
        except Exception:
            # Never fail collection due to normalization
            pass

    # Normalize item paths with leading '//' so session.bestrelpath doesn't crash
    for item in items:
        try:
            item_path = getattr(item, 'path', None)
            if item_path is None:
                continue
            item_path_str = str(item_path)
            if item_path_str.startswith('//'):
                normalized = Path('/' + item_path_str.lstrip('/'))
                # Prefer private storage if present
                if hasattr(item, '_path'):
                    setattr(item, '_path', normalized)
                else:
                    try:
                        setattr(item, 'path', normalized)
                    except Exception:
                        pass
        except Exception:
            # Do not break collection
            pass


def _normalize_item_node_and_path(item) -> None:
    """Coerce leading '//' in both item.nodeid and item.path before running the test."""
    try:
        nodeid = getattr(item, 'nodeid', None)
        if isinstance(nodeid, str):
            path_part, sep, rest = nodeid.partition('::')
            if path_part.startswith('//'):
                normalized_path = '/' + path_part.lstrip('/')
                setattr(item, '_nodeid', normalized_path + (sep + rest if sep else ''))
    except Exception:
        pass

    try:
        item_path = getattr(item, 'path', None)
        if item_path is not None:
            item_path_str = str(item_path)
            if item_path_str.startswith('//'):
                normalized = Path('/' + item_path_str.lstrip('/'))
                if hasattr(item, '_path'):
                    setattr(item, '_path', normalized)
                else:
                    try:
                        setattr(item, 'path', normalized)
                    except Exception:
                        pass
    except Exception:
        pass


@hookimpl(tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    # Ensure paths are normalized before pytest computes item.location
    _normalize_item_node_and_path(item)
    if nextitem is not None:
        _normalize_item_node_and_path(nextitem)
    # Let other plugins handle running the test
    # Returning None continues normal processing
    return None


def pytest_runtest_logreport(report):
    """Normalize report.nodeid paths to avoid leading '//' which breaks pathlib.relative_to.

    Some environments may emit absolute file paths in nodeids with a double leading slash
    (e.g., "//Users/...") which Python's pathlib can treat as a distinct root and thus
    cause ValueError during pytest's cwd-relative formatting. We coerce such paths to a
    single leading slash while preserving the rest of the nodeid (including any ::qualifiers).
    """
    try:
        nodeid = getattr(report, 'nodeid', None)
        if not isinstance(nodeid, str):
            return

        # Separate the path portion from test qualifiers
        path_part, sep, rest = nodeid.partition('::')

        # Only normalize if the path begins with a double slash
        if path_part.startswith('//'):
            normalized_path = '/' + path_part.lstrip('/')
            report.nodeid = normalized_path + (sep + rest if sep else '')
    except Exception:
        # Never let reporting normalization crash the test run
        pass
