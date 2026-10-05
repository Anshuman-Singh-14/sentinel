"""Administrative command line (03-logging-audit.md section 1).

    docker compose exec api python -m app.cli create-admin --username alice
    docker compose exec -T api python -m app.cli admin-exists   # exit 0 yes, 3 no

The first admin is created here, never through a default password. The
password is read from an interactive prompt (twice, not echoed) or, for
automation, from standard input with ``--password-stdin``. It is never
accepted as a command-line argument, because arguments are visible to other
processes (``ps``) and are saved in shell history.

Creation is audited as ``user.created`` with ``actor_type=system`` and
``service=cli``.

``admin-exists`` is a read-only probe for the host launcher ``run.py``
(ADR 0013), which offers to create the first admin only when there is none.
It answers with an exit code, so nothing about the accounts is printed.
"""

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence

from sqlalchemy import func, select

from app.config import get_settings
from app.core.audit import build_audit_service
from app.core.audit.context import SYSTEM_ACTOR
from app.core.auth.passwords import password_problems
from app.core.auth.roles import Role
from app.core.auth.users import create_user, normalize_username
from app.core.errors import SentinelError
from app.core.logging import configure_logging
from app.db.models.user import User
from app.db.session import dispose_engine, get_sessionmaker

# Exit code for "no active admin". Distinct from 1 (error) and 2 (argparse
# usage error), so the launcher can tell "none yet" from "could not check".
NO_ADMIN_EXIT_CODE = 3


def _read_password(from_stdin: bool, username: str) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != password:
            raise SystemExit("Passwords do not match.")
    problems = password_problems(password, username=username)
    if problems:
        raise SystemExit("Password rejected:\n  - " + "\n  - ".join(problems))
    return password


async def create_admin(username: str, password: str) -> str:
    """Create an admin account. Returns the normalised username."""
    audit = build_audit_service("cli")
    try:
        async with get_sessionmaker()() as db:
            user = await create_user(
                db,
                audit,
                actor=SYSTEM_ACTOR,
                username=username,
                password=password,
                role=Role.ADMIN,
            )
            return user.username
    finally:
        await dispose_engine()


async def admin_exists() -> bool:
    """True if at least one active admin account exists."""
    try:
        async with get_sessionmaker()() as db:
            count = await db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.role == Role.ADMIN.value, User.is_active.is_(True))
            )
            return bool(count)
    finally:
        await dispose_engine()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Sentinel admin CLI")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-admin", help="create an administrator account")
    create.add_argument("--username", required=True)
    create.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from the first line of standard input",
    )
    commands.add_parser(
        "admin-exists",
        help=f"exit 0 if an active admin exists, {NO_ADMIN_EXIT_CODE} if none (read-only)",
    )
    args = parser.parse_args(argv)

    configure_logging(get_settings(), service="cli")
    if args.command == "admin-exists":
        return 0 if asyncio.run(admin_exists()) else NO_ADMIN_EXIT_CODE
    try:
        username = normalize_username(args.username)
        password = _read_password(args.password_stdin, username)
        created = asyncio.run(create_admin(username, password))
    except SentinelError as exc:
        print(f"Error: {exc.message}", file=sys.stderr)
        return 1
    print(f"Admin user '{created}' created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
