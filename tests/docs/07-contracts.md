# Contracts (Protocols)

## What it is

Contracts are Python `Protocol` interfaces that describe how components should behave (methods, inputs, outputs). They decouple tests from concrete implementations and make behaviors explicit.

## Benefits

- Stable interfaces across refactors
- Clear expectations for methods and data shapes
- Interchangeable implementations (real, mock, emulator)
- Better test readability and failure messages

## Simple example

```python
from typing import Protocol

class UsersStore(Protocol):
    def create(self, user: dict) -> bool: ...

def accepts_store(store: UsersStore) -> bool:
    return store.create({"username": "ana", "password": "x"})
```


