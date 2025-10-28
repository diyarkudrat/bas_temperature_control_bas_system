# Testing

## Run Tests on Pico
```bash
scripts/repl.sh
>>> import tests.test_runner as t
>>> t.main()
```

## Test API from Computer
```bash
python3 tools/test_api.py
```

## Notes
- Unit tests under `tests/unit/*`
- Firestore DAL examples: `docs/database/10-testing.md`
- Emulator-based testing for Firestore; rate-limit logic with Redis locally
