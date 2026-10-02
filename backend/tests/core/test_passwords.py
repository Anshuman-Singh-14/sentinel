"""Argon2id hashing, the password policy and token helpers."""

import pytest

from app.core.auth.passwords import (
    MAX_LENGTH,
    MIN_LENGTH,
    dummy_hash,
    enforce_password_policy,
    hash_password,
    needs_rehash,
    password_problems,
    verify_password,
)
from app.core.auth.tokens import hash_token, is_plausible_token, new_token, tokens_equal
from app.core.errors import PasswordPolicyViolation

GOOD_PASSWORD = "test-password-123"


async def test_hash_is_argon2id_and_verifies() -> None:
    hashed = await hash_password(GOOD_PASSWORD)

    assert hashed.startswith("$argon2id$")
    assert GOOD_PASSWORD not in hashed
    assert await verify_password(hashed, GOOD_PASSWORD)
    assert not await verify_password(hashed, GOOD_PASSWORD + "x")


async def test_same_password_hashes_differently() -> None:
    # A random salt per hash: identical passwords are not identifiable in the DB.
    assert await hash_password(GOOD_PASSWORD) != await hash_password(GOOD_PASSWORD)


async def test_malformed_hash_fails_closed() -> None:
    assert not await verify_password("not-a-hash", GOOD_PASSWORD)
    assert needs_rehash("not-a-hash")


async def test_current_hash_needs_no_rehash() -> None:
    assert not needs_rehash(await hash_password(GOOD_PASSWORD))


def test_dummy_hash_is_a_real_hash_and_cached() -> None:
    assert dummy_hash().startswith("$argon2id$")
    assert dummy_hash() is dummy_hash()


def test_good_password_passes_policy() -> None:
    assert password_problems(GOOD_PASSWORD, username="alice") == []
    enforce_password_policy(GOOD_PASSWORD, username="alice")


@pytest.mark.parametrize(
    ("password", "fragment"),
    [
        ("short-1A", f"at least {MIN_LENGTH}"),
        ("x" * (MAX_LENGTH + 1), f"at most {MAX_LENGTH}"),
        ("abababababababab", "different characters"),
        ("password1234", "too common"),
        ("PassWord1234", "too common"),  # case-insensitive blocklist
        ("my-alice-secret-99", "username"),
    ],
)
def test_policy_rejects(password: str, fragment: str) -> None:
    problems = password_problems(password, username="alice")
    assert any(fragment in problem for problem in problems), problems


def test_policy_error_never_echoes_the_password() -> None:
    with pytest.raises(PasswordPolicyViolation) as exc_info:
        enforce_password_policy("password1234")
    assert "password1234" not in str(exc_info.value.details)
    assert exc_info.value.status_code == 422


def test_tokens_are_long_random_and_hashed() -> None:
    first, second = new_token(), new_token()
    assert first != second
    assert len(first) >= 43  # 256 bits, URL-safe base64
    assert hash_token(first) != first
    assert len(hash_token(first)) == 64
    assert hash_token(first) == hash_token(first)


def test_token_plausibility_and_comparison() -> None:
    token = new_token()
    assert is_plausible_token(token)
    assert not is_plausible_token(None)
    assert not is_plausible_token("")
    assert not is_plausible_token("x" * 65)
    assert tokens_equal(token, token)
    assert not tokens_equal(token, new_token())
