# tests/mock_core_objects.py
class FakeClock:
    def __init__(self):
        self._t = 0  # ms

    def now_ms(self):
        return self._t

    def advance(self, ms: int):
        self._t += int(ms)

    def elapsed_ms(self, start_ms: int) -> int:
        return self._t - start_ms


class MockRelay:
    def __init__(self, name="RELAY"):
        self.name = name
        self._on = False

    def on(self):
        self._on = True

    def off(self):
        self._on = False

    def is_on(self):
        return self._on

    def __repr__(self):
        return f"<MockRelay {self.name}={'ON' if self._on else 'OFF'}>"


class MockSensor:
    """
    Feed temperatures (tenths °C). Set ok=False to simulate fault.
    """
    def __init__(self, initial_tenths=230, ok=True):
        self.value = int(initial_tenths)
        self.ok = ok

    def set_temp_c(self, c_float):
        self.value = int(round(c_float * 10))

    def fault(self):
        self.ok = False

    def heal(self):
        self.ok = True

    def read(self):
        class Reading:
            pass
        r = Reading()
        r.ok = self.ok
        r.c_tenths = self.value if self.ok else 0
        return r
