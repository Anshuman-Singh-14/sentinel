"""One asyncio event loop per Celery worker process (ADR 0006).

Celery tasks are synchronous functions; Sentinel's tools, database and Redis
clients are async. Two obvious bridges are wrong:

* ``asyncio.run()`` per task creates and closes a loop every time. The
  SQLAlchemy/asyncpg pool and the Redis client are bound to the loop that
  created them, so the second task would use connections from a dead loop.
* A loop shared across a ``fork`` breaks in the child.

So each worker *process* lazily creates its own loop on first use (after the
prefork fork) and keeps it for its lifetime. With the prefork pool a process
runs one task at a time, so the loop is never re-entered.

If a task is interrupted by Celery's soft time limit, the exception lands at
an arbitrary await point and can leave the loop's state inconsistent.
``reset_loop()`` then abandons the loop together with every client bound to it.
"""

import asyncio
import contextlib
from collections.abc import Coroutine
from typing import Any

from app.core.runs import events
from app.db import session as db_session

_loop: asyncio.AbstractEventLoop | None = None


def run_async[T](coro: Coroutine[Any, Any, T]) -> T:
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)
    return _loop.run_until_complete(coro)


def reset_loop() -> None:
    """Drop the loop and the clients bound to it; the next task starts fresh."""
    global _loop
    loop, _loop = _loop, None
    db_session.forget_engine()
    events.forget_client()
    if loop is not None and not loop.is_closed():
        for task in asyncio.all_tasks(loop):
            task.cancel()
        # Best effort: the loop is being discarded either way.
        with contextlib.suppress(Exception):
            loop.run_until_complete(asyncio.sleep(0))
        loop.close()
