# tests/test_logging_overrides.py

from services.logging import LoggerFactory, LogLevel  # use concrete module to avoid fallback


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg}: expected {b}, got {a}")


def assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(msg or "condition was false")


def assert_false(cond, msg=""):
    if cond:
        raise AssertionError(msg or "condition was true")


def test_overrides_vs_global():
    a = LoggerFactory.get_logger("OverrideA")
    b = LoggerFactory.get_logger("OverrideB")
    a.set_print_enabled(False)
    b.set_print_enabled(False)

    # Global INFO baseline
    LoggerFactory.set_global_level(LogLevel.INFO)
    assert_eq(a.level, LogLevel.INFO, "A follows INFO")
    assert_eq(b.level, LogLevel.INFO, "B follows INFO")

    # Override B to ERROR, raise global to DEBUG; B should remain ERROR
    LoggerFactory.override_level("OverrideB", LogLevel.ERROR)
    LoggerFactory.set_global_level(LogLevel.DEBUG)
    assert_eq(a.level, LogLevel.DEBUG, "A follows global DEBUG")
    assert_eq(b.level, LogLevel.ERROR, "B keeps ERROR override")

    # Override print on A, then globally disable; A stays True, B becomes False
    LoggerFactory.override_print("OverrideA", True)
    LoggerFactory.set_print_enabled(False)
    assert_true(a._print_enabled, "A print remains True")
    assert_false(b._print_enabled, "B print is False globally")


def test_clear_overrides_sync():
    c = LoggerFactory.get_logger("OverrideC")
    c.set_print_enabled(False)
    LoggerFactory.set_global_level(LogLevel.WARNING)
    LoggerFactory.override_level("OverrideC", LogLevel.ERROR)
    assert_eq(c.level, LogLevel.ERROR, "C set to ERROR")

    LoggerFactory.clear_level_override("OverrideC")
    assert_eq(c.level, LogLevel.WARNING, "C synced to global WARNING")

    LoggerFactory.override_print("OverrideC", True)
    assert_true(c._print_enabled, "C print True overridden")
    LoggerFactory.set_print_enabled(False)
    LoggerFactory.clear_print_override("OverrideC")
    assert_false(c._print_enabled, "C print synced to global False")


def run():
    test_overrides_vs_global()
    test_clear_overrides_sync()
    print("✓ Logging overrides tests passed")


if __name__ == "__main__":
    run()


