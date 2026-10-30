from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from pymongo.database import Database

from app.privacy import record_security_event

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
ROLES = {"admin", "manager", "employee"}
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,190}\.[^@\s]{2,63}$")
ACCESS_TOKEN_MINUTES = 30
MAX_FAILED_LOGINS = 5
MAX_FAILED_IP_LOGINS = 30
LOCKOUT_MINUTES = 15


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def jwt_secret() -> str:
    value = os.getenv("JWT_SECRET", "")
    environment = os.getenv("ENVIRONMENT", "development").lower()
    if not value:
        if environment == "production":
            raise RuntimeError("JWT_SECRET must be set in production.")
        value = getattr(jwt_secret, "_development_secret", "")
        if not value:
            value = secrets.token_urlsafe(48)
            setattr(jwt_secret, "_development_secret", value)
    if len(value.encode("utf-8")) < 32:
        raise RuntimeError("JWT_SECRET must contain at least 32 bytes.")
    return value


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if not EMAIL_RE.fullmatch(normalized):
        raise HTTPException(422, "Enter a valid email address.")
    return normalized


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(encoded: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(encoded, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def email_key(email: str) -> str:
    return hashlib.sha256(email.encode("utf-8")).hexdigest()


def issue_session(
    database: Database, user: dict[str, Any], organization_id: str
) -> tuple[str, datetime]:
    issued = utc_now()
    expires = issued + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    session_id = secrets.token_urlsafe(24)
    database.sessions.insert_one(
        {
            "session_id": session_id,
            "user_id": user["user_id"],
            "organization_id": organization_id,
            "created_at": issued,
            "expires_at": expires,
            "revoked_at": None,
        }
    )
    token = jwt.encode(
        {
            "sub": user["user_id"],
            "sid": session_id,
            "org": organization_id,
            "iat": issued,
            "exp": expires,
            "iss": "smriti-nexus",
        },
        jwt_secret(),
        algorithm="HS256",
    )
    return token, expires


def enforce_login_rate_limit(
    database: Database, normalized_email: str, network_key: str | None = None
) -> dict[str, Any]:
    keys = [(email_key(normalized_email), MAX_FAILED_LOGINS)]
    if network_key:
        keys.append((network_key, MAX_FAILED_IP_LOGINS))
    now = utc_now()
    for key, _threshold in keys:
        attempt = database.login_attempts.find_one({"key": key})
        if (
            attempt
            and attempt.get("locked_until")
            and to_utc(attempt["locked_until"]) > now
        ):
            record_security_event(
                database,
                organization_id=None,
                action="auth.rate_limited",
                outcome="blocked",
                actor=key,
                severity="high",
            )
            raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.")
        if attempt and attempt.get("window_started_at"):
            age = now - to_utc(attempt["window_started_at"])
            if age > timedelta(minutes=LOCKOUT_MINUTES):
                database.login_attempts.update_one(
                    {"key": key},
                    {
                        "$set": {
                            "window_started_at": now,
                            "failed_count": 0,
                            "locked_until": None,
                        }
                    },
                )
    return {"keys": keys}


def record_failed_login(database: Database, key: str, threshold: int) -> None:
    now = utc_now()
    attempt = database.login_attempts.find_one({"key": key})
    if not attempt or now - to_utc(attempt.get("window_started_at", now)) > timedelta(
        minutes=LOCKOUT_MINUTES
    ):
        database.login_attempts.update_one(
            {"key": key},
            {
                "$set": {
                    "window_started_at": now,
                    "failed_count": 1,
                    "locked_until": None,
                }
            },
            upsert=True,
        )
        failed_count = 1
    else:
        result = database.login_attempts.find_one_and_update(
            {"key": key},
            {"$inc": {"failed_count": 1}},
            return_document=True,
        )
        failed_count = int((result or {}).get("failed_count", 1))
    locked_until = (
        now + timedelta(minutes=LOCKOUT_MINUTES)
        if failed_count >= threshold
        else None
    )
    database.login_attempts.update_one(
        {"key": key}, {"$set": {"locked_until": locked_until}}
    )


def get_database(request: Request) -> Database:
    database = getattr(request.app.state, "database", None)
    if database is None:
        raise HTTPException(503, "The database is not available.")
    return database


def current_principal(
    request: Request, database: Database = Depends(get_database)
) -> dict[str, Any]:
    if os.getenv("DEMO_MODE", "").lower() == "true":
        client_host = request.client.host if request.client else ""
        try:
            is_local_client = ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            is_local_client = False
        if (
            os.getenv("ENVIRONMENT", "development").lower() == "production"
            or not is_local_client
        ):
            raise HTTPException(403, "Local demo access is restricted to this computer.")
        return {
            "user_id": "local-demo-user",
            "email": "demo@localhost",
            "organization_id": "local-demo",
            "role": "admin",
            "session_id": "local-demo-session",
        }

    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "Sign in to continue.")
    try:
        claims = jwt.decode(
            token,
            jwt_secret(),
            algorithms=["HS256"],
            issuer="smriti-nexus",
            options={"require": ["exp", "iat", "sub", "sid", "org"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(401, "Your session expired. Sign in again.") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, "Your session is invalid. Sign in again.") from exc

    session = database.sessions.find_one(
        {
            "session_id": claims["sid"],
            "user_id": claims["sub"],
            "organization_id": claims["org"],
            "revoked_at": None,
            "expires_at": {"$gt": utc_now()},
        }
    )
    user = database.users.find_one(
        {"user_id": claims["sub"], "status": "active"},
        {"_id": 0, "password_hash": 0},
    )
    membership = database.memberships.find_one(
        {
            "user_id": claims["sub"],
            "organization_id": claims["org"],
            "status": "active",
        }
    )
    if not session or not user or not membership:
        raise HTTPException(401, "Your session is no longer active. Sign in again.")
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "organization_id": membership["organization_id"],
        "role": membership["role"],
        "session_id": session["session_id"],
    }


def require_roles(*roles: str):
    allowed = set(roles)

    def dependency(principal: dict[str, Any] = Depends(current_principal)):
        if principal["role"] not in allowed:
            raise HTTPException(403, "Your organization role does not allow this action.")
        return principal

    return dependency


def audit_actor(principal: dict[str, Any]) -> str:
    return principal["user_id"]
