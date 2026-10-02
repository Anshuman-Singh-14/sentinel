"""Celery queue names. Kept separate from the Celery app so tool metadata can
reference them without importing Celery or reading broker settings."""

DEFAULT_QUEUE = "default"
SCANS_QUEUE = "scans"  # long-running active tools (port scans)
INTEL_QUEUE = "intel"  # rate-limited third-party API calls

QUEUES = (DEFAULT_QUEUE, SCANS_QUEUE, INTEL_QUEUE)
