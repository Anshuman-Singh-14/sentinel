"""Login, refresh, logout, password change and session validation.

Every outcome is audited (Phase 2 acceptance: "every auth action produces an
audit event"). Successful actions are audited inside the same transaction as
the change, so a session can never exist without its login event. Failures
are audited on their own transaction after rolling back, so they are recorded
even though nothing else is.

Login failures are indistinguishable to the client (``InvalidCredentials``);
the specific reason (unknown_user, bad_password, account_locked,
account_disabled, rate_limited) is recorded only in the audit log.
"""

import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.audit import Actor, AuditAction, AuditService, Outcome
from app.core.auth.cookies import IssuedTokens
from app.core.auth.passwords import (
    dummy_hash,
    enforce_password_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.core.auth.tokens import hash_token, is_plausible_token, new_token
from app.core.errors import (
    AuthenticationRequired,
    InvalidCredentials,
    PasswordPolicyViolation,
    PermissionDenied,
)
from app.core.ids import uuid7
from app.core.ratelimit import RateLimiter, raise_if_limited
from app.db.models import User, UserSession
from app.db.models._types import utcnow

# last_seen_at is written at most this often, so authenticated reads do not
# each cost a database write.
LAST_SEEN_RESOLUTION = timedelta(seconds=60)
RATE_WINDOW_SECONDS = 60
PASSWORD_CHANGE_LIMIT_PER_MINUTE = 5
# Caps 2**n in the lockout calculation; the configured maximum applies anyway.
_MAX_LOCKOUT_EXPONENT = 20


@dataclass(frozen=True)
class IssuedSession:
    session: UserSession
    user: User
    tokens: IssuedTokens


def user_actor(base: Actor, user: User, session_id: uuid.UUID | None) -> Actor:
    return base.as_user(
        user_id=user.id, username=user.username, role=user.role, session_id=session_id
    )


class AuthService:
    def __init__(
        self,
        db: AsyncSession,
        audit: AuditService,
        limiter: RateLimiter,
        settings: Settings,
    ) -> None:
        self._db = db
        self._audit = audit
        self._limiter = limiter
        self._settings = settings

    # ------------------------------------------------------------------ login

    async def login(self, username: str, password: str, actor: Actor) -> IssuedSession:
        settings = self._settings
        normalized = username.strip().lower()
        attempt_actor = replace(actor, username=normalized)

        limit = await self._limiter.hit(
            f"login:ip:{actor.source_ip or 'unknown'}",
            limit=settings.auth_rate_limit_per_minute,
            window_seconds=RATE_WINDOW_SECONDS,
        )
        if not limit.allowed:
            await self._login_failed(attempt_actor, "rate_limited", outcome=Outcome.DENIED)
            raise_if_limited(limit)

        # FOR UPDATE serialises concurrent attempts on one account, so parallel
        # guesses cannot race past the failure counter.
        user = await self._db.scalar(
            select(User).where(User.username == normalized).with_for_update()
        )
        now = utcnow()

        if user is None:
            # Burn the same time as a real check (no user enumeration by timing).
            await verify_password(dummy_hash(), password)
            await self._login_failed(attempt_actor, "unknown_user")
            raise InvalidCredentials
        attempt_actor = replace(attempt_actor, user_id=user.id)

        if not user.is_active:
            await verify_password(dummy_hash(), password)
            await self._login_failed(attempt_actor, "account_disabled")
            raise InvalidCredentials
        if user.locked_until is not None and user.locked_until > now:
            await verify_password(dummy_hash(), password)
            await self._login_failed(
                attempt_actor,
                "account_locked",
                details={"locked_until": user.locked_until.isoformat()},
            )
            raise InvalidCredentials

        if not await verify_password(user.password_hash, password):
            await self._record_bad_password(user, attempt_actor, now)
            raise InvalidCredentials

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        if needs_rehash(user.password_hash):
            user.password_hash = await hash_password(password)
        session, tokens = self._new_session(user, actor, now)
        await self._audit.record(
            AuditAction.AUTH_LOGIN_SUCCESS,
            actor=user_actor(actor, user, session.id),
            outcome=Outcome.SUCCESS,
            resource_type="session",
            resource_id=str(session.id),
            session=self._db,
        )
        await self._db.commit()
        return IssuedSession(session=session, user=user, tokens=tokens)

    async def _record_bad_password(self, user: User, actor: Actor, now: datetime) -> None:
        settings = self._settings
        user.failed_login_count += 1
        failed = user.failed_login_count
        lock_seconds: int | None = None
        if failed >= settings.login_max_failures:
            # Exponential backoff: base, 2x base, 4x base... up to the maximum.
            exponent = min(failed - settings.login_max_failures, _MAX_LOCKOUT_EXPONENT)
            lock_seconds = min(
                settings.lockout_base_seconds * 2**exponent, settings.lockout_max_seconds
            )
            user.locked_until = now + timedelta(seconds=lock_seconds)
        await self._db.commit()

        await self._audit.record(
            AuditAction.AUTH_LOGIN_FAILURE,
            actor=actor,
            outcome=Outcome.FAILURE,
            target=actor.username,
            reason="bad_password",
            details={"failed_count": failed},
        )
        if lock_seconds is not None:
            await self._audit.record(
                AuditAction.AUTH_LOCKOUT,
                actor=actor,
                outcome=Outcome.SUCCESS,
                resource_type="user",
                resource_id=str(user.id),
                target=actor.username,
                reason="too_many_failures",
                details={"failed_count": failed, "locked_seconds": lock_seconds},
            )

    async def _login_failed(
        self,
        actor: Actor,
        reason: str,
        *,
        outcome: Outcome = Outcome.FAILURE,
        details: dict[str, object] | None = None,
    ) -> None:
        await self._db.rollback()  # release any row lock before the audit write
        await self._audit.record(
            AuditAction.AUTH_LOGIN_FAILURE,
            actor=actor,
            outcome=outcome,
            target=actor.username,
            reason=reason,
            details=details,
        )

    # ---------------------------------------------------------------- sessions

    def _new_session(
        self, user: User, actor: Actor, now: datetime
    ) -> tuple[UserSession, IssuedTokens]:
        settings = self._settings
        absolute = now + timedelta(hours=settings.session_absolute_hours)
        tokens = self._issue_tokens(now, absolute)
        session = UserSession(
            id=uuid7(),
            user_id=user.id,
            access_token_hash=hash_token(tokens.access_token),
            refresh_token_hash=hash_token(tokens.refresh_token),
            csrf_token_hash=hash_token(tokens.csrf_token),
            access_expires_at=tokens.access_expires_at,
            refresh_expires_at=tokens.refresh_expires_at,
            absolute_expires_at=absolute,
            created_at=now,
            last_seen_at=now,
            source_ip=actor.source_ip,
            user_agent=actor.user_agent,
        )
        self._db.add(session)
        return session, tokens

    def _issue_tokens(self, now: datetime, absolute: datetime) -> IssuedTokens:
        settings = self._settings
        return IssuedTokens(
            access_token=new_token(),
            refresh_token=new_token(),
            csrf_token=new_token(),
            access_expires_at=min(
                now + timedelta(minutes=settings.access_token_ttl_minutes), absolute
            ),
            refresh_expires_at=min(
                now + timedelta(hours=settings.refresh_token_idle_hours), absolute
            ),
        )

    async def authenticate(self, access_token: str | None) -> tuple[UserSession, User] | None:
        """Resolve an access token to its live session and active user."""
        if access_token is None or not is_plausible_token(access_token):
            return None
        row = (
            await self._db.execute(
                select(UserSession, User)
                .join(User, User.id == UserSession.user_id)
                .where(UserSession.access_token_hash == hash_token(access_token))
            )
        ).one_or_none()
        if row is None:
            return None
        session, user = row.tuple()
        now = utcnow()
        if (
            session.revoked_at is not None
            or session.access_expires_at <= now
            or session.absolute_expires_at <= now
            or not user.is_active
        ):
            return None
        if now - session.last_seen_at >= LAST_SEEN_RESOLUTION:
            session.last_seen_at = now
            await self._db.commit()
        return session, user

    async def refresh(self, refresh_token: str | None, actor: Actor) -> IssuedSession:
        settings = self._settings
        limit = await self._limiter.hit(
            f"refresh:ip:{actor.source_ip or 'unknown'}",
            limit=settings.auth_rate_limit_per_minute,
            window_seconds=RATE_WINDOW_SECONDS,
        )
        if not limit.allowed:
            await self._refresh_failed(actor, "rate_limited", outcome=Outcome.DENIED)
            raise_if_limited(limit)
        if refresh_token is None or not is_plausible_token(refresh_token):
            await self._refresh_failed(actor, "missing_token")
            raise AuthenticationRequired

        token_hash = hash_token(refresh_token)
        session = await self._db.scalar(
            select(UserSession)
            .where(UserSession.refresh_token_hash == token_hash)
            .with_for_update()
        )
        now = utcnow()
        if session is None:
            await self._handle_unknown_refresh(token_hash, actor, now)
            raise AuthenticationRequired

        user = await self._db.get(User, session.user_id)
        reason = self._refresh_rejection(session, user, now)
        if reason is not None or user is None:
            failed_actor = replace(actor, user_id=session.user_id, session_id=session.id)
            await self._refresh_failed(failed_actor, reason or "user_missing")
            raise AuthenticationRequired

        tokens = self._issue_tokens(now, session.absolute_expires_at)
        session.previous_refresh_token_hash = session.refresh_token_hash
        session.refresh_token_hash = hash_token(tokens.refresh_token)
        session.access_token_hash = hash_token(tokens.access_token)
        session.csrf_token_hash = hash_token(tokens.csrf_token)
        session.access_expires_at = tokens.access_expires_at
        session.refresh_expires_at = tokens.refresh_expires_at
        session.last_seen_at = now
        await self._audit.record(
            AuditAction.AUTH_TOKEN_REFRESH,
            actor=user_actor(actor, user, session.id),
            outcome=Outcome.SUCCESS,
            resource_type="session",
            resource_id=str(session.id),
            session=self._db,
        )
        await self._db.commit()
        return IssuedSession(session=session, user=user, tokens=tokens)

    @staticmethod
    def _refresh_rejection(session: UserSession, user: User | None, now: datetime) -> str | None:
        if session.revoked_at is not None:
            return "session_revoked"
        if session.refresh_expires_at <= now or session.absolute_expires_at <= now:
            return "session_expired"
        if user is None or not user.is_active:
            return "account_disabled"
        return None

    async def _handle_unknown_refresh(self, token_hash: str, actor: Actor, now: datetime) -> None:
        """A refresh token that is not current. If it is the *previous* token of
        a live session, a copy was used after rotation: revoke the session."""
        reused = await self._db.scalar(
            select(UserSession)
            .where(UserSession.previous_refresh_token_hash == token_hash)
            .with_for_update()
        )
        if reused is None or reused.revoked_at is not None:
            await self._refresh_failed(actor, "unknown_token")
            return
        owner = await self._db.get(User, reused.user_id)
        reused.revoked_at = now
        reused.revoked_reason = "refresh_token_reuse"
        # The presenter is unknown (could be the attacker), so the actor stays
        # anonymous; the owner's identity goes in the user fields for triage.
        revoked = await self._audit.record(
            AuditAction.AUTH_SESSION_REVOKED,
            actor=replace(
                actor,
                user_id=reused.user_id,
                username=owner.username if owner else None,
                session_id=reused.id,
            ),
            outcome=Outcome.SUCCESS,
            resource_type="session",
            resource_id=str(reused.id),
            reason="refresh_token_reuse",
            session=self._db,
        )
        await self._db.commit()
        await self._audit.after_commit(revoked)  # raises the token-reuse alert
        await self._refresh_failed(
            replace(actor, user_id=reused.user_id, session_id=reused.id), "refresh_token_reuse"
        )

    async def _refresh_failed(
        self, actor: Actor, reason: str, *, outcome: Outcome = Outcome.FAILURE
    ) -> None:
        await self._db.rollback()
        await self._audit.record(
            AuditAction.AUTH_TOKEN_REFRESH, actor=actor, outcome=outcome, reason=reason
        )

    async def find_session_for_logout(
        self, access_token: str | None, refresh_token: str | None
    ) -> tuple[UserSession, User] | None:
        """Logout works with either cookie, so an expired access token does
        not leave the user unable to end their session."""
        for column, token in (
            (UserSession.access_token_hash, access_token),
            (UserSession.refresh_token_hash, refresh_token),
        ):
            if token is None or not is_plausible_token(token):
                continue
            row = (
                await self._db.execute(
                    select(UserSession, User)
                    .join(User, User.id == UserSession.user_id)
                    .where(column == hash_token(token), UserSession.revoked_at.is_(None))
                )
            ).one_or_none()
            if row is not None:
                session, user = row.tuple()
                return session, user
        return None

    async def logout(self, session: UserSession, user: User, actor: Actor) -> None:
        session.revoked_at = utcnow()
        session.revoked_reason = "logout"
        await self._audit.record(
            AuditAction.AUTH_LOGOUT,
            actor=user_actor(actor, user, session.id),
            outcome=Outcome.SUCCESS,
            resource_type="session",
            resource_id=str(session.id),
            session=self._db,
        )
        await self._db.commit()

    async def get_user(self, user_id: uuid.UUID) -> User:
        user = await self._db.get(User, user_id)
        if user is None:
            raise AuthenticationRequired
        return user

    # --------------------------------------------------------------- passwords

    async def change_password(
        self, user_id: uuid.UUID, session_id: uuid.UUID, current: str, new: str, actor: Actor
    ) -> None:
        limit = await self._limiter.hit(
            f"password:user:{user_id}",
            limit=PASSWORD_CHANGE_LIMIT_PER_MINUTE,
            window_seconds=RATE_WINDOW_SECONDS,
        )
        raise_if_limited(limit)
        user = await self._db.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise AuthenticationRequired
        if not await verify_password(user.password_hash, current):
            await self._db.rollback()
            await self._audit.record(
                AuditAction.USER_PASSWORD_CHANGED,
                actor=actor,
                outcome=Outcome.FAILURE,
                resource_type="user",
                resource_id=str(user_id),
                reason="bad_current_password",
            )
            raise PermissionDenied("The current password is incorrect.")
        if current == new:
            raise PasswordPolicyViolation(
                details={"problems": ["The new password must differ from the current one."]}
            )
        enforce_password_policy(new, username=user.username)
        now = utcnow()
        user.password_hash = await hash_password(new)
        user.password_changed_at = now
        # Every other session ends: if the password was changed because it
        # leaked, sessions the attacker opened must not survive.
        result = await self._db.execute(
            update(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.id != session_id,
                UserSession.revoked_at.is_(None),
            )
            .values(revoked_at=now, revoked_reason="password_changed")
        )
        await self._audit.record(
            AuditAction.USER_PASSWORD_CHANGED,
            actor=actor,
            outcome=Outcome.SUCCESS,
            resource_type="user",
            resource_id=str(user.id),
            details={"revoked_count": result.rowcount},  # type: ignore[attr-defined]
            session=self._db,
        )
        await self._db.commit()
