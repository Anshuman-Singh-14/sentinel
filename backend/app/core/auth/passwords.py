"""Password hashing (Argon2id) and the password policy.

Hashing: argon2-cffi's default parameters follow RFC 9106's second recommended
profile (Argon2id, t=3, m=64 MiB, p=4). Each hash deliberately costs ~64 MiB
of RAM and tens of milliseconds, which is what makes offline cracking
expensive. Two consequences handled here:

* Hashing runs in a worker thread, so it never blocks the event loop.
* A semaphore caps concurrent hashes at ``MAX_CONCURRENT_HASHES``, so a burst
  of logins cannot exhaust memory (64 MiB x the default 40 threads would be
  2.5 GiB). It is a thread-level semaphore, acquired inside the worker thread,
  so it works whichever event loop is running. The per-IP login rate limit
  bounds the load further.

Policy: NIST SP 800-63B favours length and a blocklist over composition rules
("one upper, one digit..."), which push users towards predictable patterns.
"""

import secrets
import threading
from functools import lru_cache
from importlib import resources

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.errors import PasswordPolicyViolation

MIN_LENGTH = 12
# An upper bound stops multi-megabyte "passwords" being fed to the hasher.
MAX_LENGTH = 128
MIN_DISTINCT_CHARACTERS = 5
MAX_CONCURRENT_HASHES = 4

_hasher = PasswordHasher()
_hash_slots = threading.BoundedSemaphore(MAX_CONCURRENT_HASHES)


def _hash(password: str) -> str:
    with _hash_slots:
        return _hasher.hash(password)


def _verify(password_hash: str, password: str) -> bool:
    with _hash_slots:
        try:
            return _hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


async def hash_password(password: str) -> str:
    return await anyio.to_thread.run_sync(_hash, password)


async def verify_password(password_hash: str, password: str) -> bool:
    return await anyio.to_thread.run_sync(_verify, password_hash, password)


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash used older parameters; rehash on next login."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


@lru_cache
def dummy_hash() -> str:
    """A real Argon2 hash of a random value, verified against when the
    username does not exist, so unknown and known users take the same time."""
    return _hasher.hash(secrets.token_urlsafe(32))


@lru_cache
def _blocklist() -> frozenset[str]:
    text = resources.files("app.core.auth").joinpath("common_passwords.txt").read_text("utf-8")
    return frozenset(
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )


def password_problems(password: str, *, username: str | None = None) -> list[str]:
    """Every policy violation, as user-facing messages (empty list = acceptable)."""
    problems: list[str] = []
    if len(password) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
    if len(password) > MAX_LENGTH:
        problems.append(f"Use at most {MAX_LENGTH} characters.")
    if len(set(password)) < MIN_DISTINCT_CHARACTERS:
        problems.append(f"Use at least {MIN_DISTINCT_CHARACTERS} different characters.")
    lowered = password.lower()
    if username and len(username) >= 3 and username.lower() in lowered:
        problems.append("Do not include your username in the password.")
    if lowered in _blocklist():
        problems.append("This password is too common. Choose a less predictable one.")
    return problems


def enforce_password_policy(password: str, *, username: str | None = None) -> None:
    problems = password_problems(password, username=username)
    if problems:
        # Messages describe the rule broken, never echo the password.
        raise PasswordPolicyViolation(details={"problems": problems})
