"""Shared test configuration.

Settings are read from the environment at import time, so safe dummy values
are set before any ``app`` module is imported. Tests never touch real services:
dependency checks are monkeypatched.
"""

import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@127.0.0.1:1/test")
os.environ.setdefault("REDIS_URL", "redis://:test@127.0.0.1:1/0")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:5173")
