# Simple Explanation

Think of the database like a well-organized filing system:

1. Telemetry is a stack of time-stamped notes from each device.
2. Users are the list of people allowed to use the system.
3. Sessions are temporary visitor badges that expire.
4. Audit logs are the security camera footage—who did what and when.
5. Devices is the catalog of equipment.

Key safety rules:
- Every file is labeled with a tenant, so people only see their own files.
- Old notes are automatically recycled after a while to save space (TTL).
- When in development, we use a local “practice” database that looks and feels like the real one.
