"""Mock exceptions for Firestore operations."""


class MockPermissionDenied(Exception):
    """Mock permission denied exception."""
    pass


class MockNotFound(Exception):
    """Mock not found exception."""
    pass


class MockUnavailable(Exception):
    """Mock unavailable exception."""
    pass


class MockDeadlineExceeded(Exception):
    """Mock deadline exceeded exception."""
    pass


class MockCancelled(Exception):
    """Mock cancelled exception."""
    pass


class MockFailedPrecondition(Exception):
    """Mock failed precondition exception."""
    pass


class MockAborted(Exception):
    """Mock aborted exception."""
    pass


class MockOutOfRange(Exception):
    """Mock out of range exception."""
    pass


class MockUnimplemented(Exception):
    """Mock unimplemented exception."""
    pass


class MockInternal(Exception):
    """Mock internal exception."""
    pass


class MockDataLoss(Exception):
    """Mock data loss exception."""
    pass


class MockUnauthenticated(Exception):
    """Mock unauthenticated exception."""
    pass