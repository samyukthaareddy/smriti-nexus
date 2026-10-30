from __future__ import annotations

import csv
import io
import logging
import os
import re
import hashlib
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError
from pymongo.database import Database
from starlette.responses import JSONResponse, StreamingResponse

from app.auth import (
    audit_actor,
    current_principal,
    email_key,
    enforce_login_rate_limit,
    get_database,
    hash_password,
    issue_session,
    jwt_secret,
    normalize_email,
    record_failed_login,
    require_roles,
    utc_now,
    verify_password,
)
from app.privacy import (
    SENSITIVITY_LEVELS,
    classify_sensitivity,
    privacy_decision,
    record_audit,
    record_security_event,
    verify_audit_hash,
)
from app.key_management import (
    content_search_tokens,
    local_master_key_configured,
    protect_content,
    query_search_tokens,
    reveal_content,
    validate_production_key_provider,
)
from app.storage import create_database, ensure_indexes

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
logger = logging.getLogger("smriti_nexus")

STATUSES = {"Verified", "Unverified", "Disputed", "Superseded", "Archived"}
MEMORY_FIELDS = (
    "id",
    "title",
    "memory_type",
    "project",
    "status",
    "content",
    "source",
    "version",
    "created_at",
    "updated_at",
    "supersedes_id",
    "sensitivity",
    "tags",
)
DEMO_SEED = [
    {
        "id": "demo-1",
        "title": "Payment timeout incident",
        "memory_type": "Incident",
        "project": "Payment Service",
        "status": "Verified",
        "content": "Repeated payment timeouts were traced to database connection-pool exhaustion under the previous service architecture. The original mitigation helped at that time.",
        "source": "incident-report-payment-014.md",
        "version": 1,
    },
    {
        "id": "demo-2",
        "title": "Connection-pool mitigation",
        "memory_type": "Fix",
        "project": "Payment Service",
        "status": "Superseded",
        "content": "Adjusting connection-pool configuration reduced timeouts in the earlier architecture. This historical guidance is no longer sufficient after the service architecture changed.",
        "source": "postmortem-payment-014.md",
        "version": 1,
    },
    {
        "id": "demo-3",
        "title": "Architecture migration changes retry behavior",
        "memory_type": "Decision",
        "project": "Payment Service",
        "status": "Verified",
        "content": "After moving to a queue-backed worker architecture, investigate queue consumer saturation, retry amplification, and downstream latency before changing pool limits. Validate changes against current telemetry.",
        "source": "architecture-review-v3.md",
        "version": 2,
    },
    {
        "id": "demo-4",
        "title": "Queue saturation under burst traffic",
        "memory_type": "Root cause",
        "project": "Payment Service",
        "status": "Unverified",
        "content": "Burst traffic may be saturating consumers. This is a hypothesis requiring telemetry confirmation; do not treat it as a verified root cause.",
        "source": "incident-followup.md",
        "version": 1,
    },
    {
        "id": "demo-5",
        "title": "Rollback guardrail",
        "memory_type": "Constraint",
        "project": "Platform Reliability",
        "status": "Verified",
        "content": "Payment-path changes must preserve idempotency and be validated with a staged rollout and an agreed rollback threshold.",
        "source": "reliability-standards.md",
        "version": 1,
    },
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def uuid_str() -> str:
    return str(uuid.uuid4())


def record_event(
    database: Database,
    principal: dict[str, Any],
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    outcome: str = "recorded",
    severity: str = "info",
    metadata: dict[str, Any] | None = None,
) -> None:
    record_audit(
        database,
        organization_id=principal["organization_id"],
        actor=audit_actor(principal),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        severity=severity,
        metadata=metadata,
    )


def memory_out(document: dict[str, Any]) -> dict[str, Any]:
    result = {key: document.get(key) for key in MEMORY_FIELDS}
    result["content"] = readable_content(document)
    return result


def readable_content(document: dict[str, Any]) -> str:
    try:
        return reveal_content(document)
    except RuntimeError as exc:
        logger.error("Memory decryption unavailable: %s", type(exc).__name__)
        raise HTTPException(
            503, "The encryption key required for this memory is unavailable."
        ) from exc


def secure_content_fields(content: str, sensitivity: str) -> dict[str, Any]:
    try:
        protected = protect_content(content, sensitivity)
    except RuntimeError as exc:
        logger.error("Sensitive memory encryption unavailable: %s", type(exc).__name__)
        raise HTTPException(
            503,
            "Confidential and Top Secret memories require a configured encryption key provider.",
        ) from exc
    if "content_envelope" in protected:
        protected["search_tokens"] = content_search_tokens(content)
    return protected


def correction_out(document: dict[str, Any], memory: dict[str, Any] | None = None) -> dict[str, Any]:
    result = {key: value for key, value in document.items() if key != "_id"}
    result["content"] = readable_content(document)
    result.setdefault("project", memory.get("project") if memory else None)
    result.setdefault("supersedes_title", memory.get("title") if memory else None)
    result["decision"] = (
        result["status"] if result["status"] in {"approved", "rejected"} else None
    )
    result["proposed_title"] = result.get("title")
    result["proposed_memory_type"] = result.get("memory_type")
    result["proposed_content"] = result.get("content")
    result["proposed_source"] = result.get("source")
    result["proposed_status"] = result.get("requested_status")
    result["note"] = result.get("review_note", "")
    return result


def org_filter(principal: dict[str, Any], **filters: Any) -> dict[str, Any]:
    return {"organization_id": principal["organization_id"], **filters}


def make_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if not slug:
        raise HTTPException(422, "Enter a valid organization name.")
    return f"{slug[:48]}-{secrets.token_hex(4)}"


def safe_name(value: str, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise HTTPException(422, f"{label} is required.")
    return cleaned


def cors_origins() -> list[str]:
    production = os.getenv("ENVIRONMENT", "development").lower() == "production"
    configured = os.getenv("ALLOWED_ORIGINS", "")
    if configured:
        origins = [origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip()]
    elif production:
        raise RuntimeError("ALLOWED_ORIGINS must list trusted frontend origins in production.")
    else:
        origins = [
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:5175",
            "http://localhost:5176",
            "http://localhost:5177",
            "http://localhost:5178",
            "http://localhost:5179",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            "http://127.0.0.1:5175",
            "http://127.0.0.1:5176",
            "http://127.0.0.1:5177",
            "http://127.0.0.1:5178",
            "http://127.0.0.1:5179",
        ]
    if "*" in origins:
        raise RuntimeError("Wildcard CORS is not allowed.")
    return origins


@asynccontextmanager
async def lifespan(app: FastAPI):
    production = os.getenv("ENVIRONMENT", "development").lower() == "production"
    demo_mode = os.getenv("DEMO_MODE", "").lower() == "true"
    if production:
        if demo_mode:
            raise RuntimeError("DEMO_MODE cannot be enabled in production.")
        jwt_secret()
        if os.getenv("LOCAL_MASTER_KEY") or os.getenv("DEV_FIELD_ENCRYPTION_KEY"):
            raise RuntimeError(
                "LOCAL_MASTER_KEY and DEV_FIELD_ENCRYPTION_KEY are development-only and cannot be configured in production."
            )
        validate_production_key_provider()
        if not os.getenv("MONGODB_URI"):
            raise RuntimeError("MONGODB_URI must be configured in production.")
    if demo_mode:
        if getattr(app.state, "database", None) is None:
            import mongomock

            demo_client = mongomock.MongoClient(tz_aware=True)
            app.state.demo_database_client = demo_client
            app.state.database = demo_client["smriti_demo"]
            ensure_indexes(app.state.database)
    elif getattr(app.state, "database", None) is None and os.getenv("MONGODB_URI"):
        app.state.database = create_database()
    if demo_mode and getattr(app.state, "database", None) is not None:
        database = app.state.database
        database.organizations.update_one(
            {"organization_id": "local-demo"},
            {
                "$setOnInsert": {
                    "organization_id": "local-demo",
                    "name": "Local Demo Workspace",
                    "slug": "local-demo",
                    "created_at": now(),
                }
            },
            upsert=True,
        )
        for item in DEMO_SEED:
            database.memories.update_one(
                {"organization_id": "local-demo", "id": item["id"]},
                {
                    "$setOnInsert": {
                        **item,
                        "organization_id": "local-demo",
                        "sensitivity": "INTERNAL",
                        "tags": [],
                        "created_at": now(),
                        "updated_at": now(),
                        "supersedes_id": None,
                    }
                },
                upsert=True,
            )
    if production and getattr(app.state, "database", None) is None:
        raise RuntimeError("MongoDB Atlas could not be initialized.")
    if not production and getattr(app.state, "database", None) is None:
        logger.warning("MongoDB is not configured; API routes will return 503.")
    yield
    demo_client = getattr(app.state, "demo_database_client", None)
    if demo_client is not None:
        demo_client.close()
        app.state.database = None
        app.state.demo_database_client = None


app = FastAPI(title="Smriti Nexus API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


class SignupInput(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(min_length=12, max_length=128)
    organization_name: str = Field(min_length=2, max_length=120)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class LoginInput(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(min_length=1, max_length=128)
    organization_id: str | None = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class InviteInput(BaseModel):
    email: str = Field(max_length=320)
    role: Literal["manager", "employee"] = "employee"

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class AcceptInvitationInput(BaseModel):
    invitation_token: str = Field(min_length=32, max_length=256)
    password: str = Field(min_length=12, max_length=128)


class MembershipUpdate(BaseModel):
    role: Literal["admin", "manager", "employee"] | None = None
    status: Literal["active", "revoked"] | None = None



class MemoryInput(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    memory_type: str = Field(default="Project context", max_length=60)
    project: str = Field(default="Payment Service", max_length=120)
    status: str = Field(default="Unverified")
    content: str = Field(min_length=1, max_length=12000)
    source: str = Field(default="manual-entry.md", max_length=240)
    supersedes_id: str | None = None
    sensitivity: str = Field(default="INTERNAL")
    tags: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("sensitivity")
    @classmethod
    def validate_sensitivity(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in SENSITIVITY_LEVELS:
            raise ValueError("Invalid sensitivity level.")
        return normalized

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str]) -> list[str]:
        return [safe_name(tag, "Tag")[:48] for tag in value]


class MemoryUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1, max_length=180)
    memory_type: str | None = Field(default=None, max_length=60)
    project: str | None = Field(default=None, max_length=120)
    status: str | None = None
    content: str | None = Field(default=None, min_length=1, max_length=12000)
    source: str | None = Field(default=None, max_length=240)
    sensitivity: str | None = None
    tags: list[str] | None = Field(default=None, max_length=30)


class CorrectionInput(BaseModel):
    memory_id: str = Field(min_length=1)
    title: str | None = Field(default=None, min_length=1, max_length=180)
    memory_type: str | None = Field(default=None, max_length=60)
    content: str = Field(min_length=1, max_length=12000)
    source: str | None = Field(default=None, max_length=240)
    requested_status: str | None = None


class CorrectionReviewInput(BaseModel):
    decision: Literal["approved", "rejected"]
    reviewer: str | None = Field(default=None, max_length=120)
    note: str = Field(default="", max_length=2000)


class AskInput(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class PrivacyPreviewInput(AskInput):
    memory_ids: list[str] = Field(default_factory=list, max_length=10)


@app.get("/api/health")
def health(database: Database = Depends(get_database)):
    try:
        database.command("ping")
        database_name = (
            "local-demo"
            if os.getenv("DEMO_MODE", "").lower() == "true"
            else "mongodb"
        )
        return {"status": "ok", "database": database_name}
    except Exception as exc:
        logger.error("MongoDB health check failed: %s", type(exc).__name__)
        raise HTTPException(503, "The database is unavailable.") from exc


@app.exception_handler(PyMongoError)
async def mongo_error_handler(request: Request, exc: PyMongoError):
    logger.error("MongoDB request failed at %s: %s", request.url.path, type(exc).__name__)
    return JSONResponse(
        status_code=503,
        content={"detail": "The database is temporarily unavailable."},
    )


@app.post("/api/auth/signup")
def signup(data: SignupInput, database: Database = Depends(get_database)):
    email = data.email
    if database.users.find_one({"email": email}, {"_id": 1}):
        raise HTTPException(409, "An account with this email already exists.")
    organization_id = uuid_str()
    user_id = uuid_str()
    organization = {
        "organization_id": organization_id,
        "name": safe_name(data.organization_name, "Organization name"),
        "slug": make_slug(data.organization_name),
        "created_at": now(),
    }
    user = {
        "user_id": user_id,
        "email": email,
        "password_hash": hash_password(data.password),
        "status": "active",
        "created_at": now(),
    }
    try:
        database.organizations.insert_one(organization)
        database.users.insert_one(user)
        database.memberships.insert_one(
            {
                "user_id": user_id,
                "organization_id": organization_id,
                "role": "admin",
                "status": "active",
                "created_at": now(),
            }
        )
        database.memories.insert_many(
            [
                {
                    **item,
                    "organization_id": organization_id,
                    "sensitivity": "INTERNAL",
                    "tags": [],
                    "created_at": now(),
                    "updated_at": now(),
                    "supersedes_id": None,
                }
                for item in DEMO_SEED
            ]
        )
    except Exception as exc:
        database.organizations.delete_one({"organization_id": organization_id})
        database.users.delete_one({"user_id": user_id})
        database.memberships.delete_one({"user_id": user_id})
        if getattr(exc, "code", None) == 11000:
            raise HTTPException(409, "An account with this email already exists.") from exc
        logger.error("Workspace signup failed: %s", type(exc).__name__)
        raise HTTPException(503, "Could not create the workspace. Try again.") from exc
    token, expires = issue_session(database, user, organization_id)
    record_security_event(
        database,
        organization_id=organization_id,
        action="auth.signup",
        outcome="success",
        actor=user_id,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires.isoformat(),
        "user": {"user_id": user_id, "email": email, "role": "admin"},
        "organization": {
            "organization_id": organization_id,
            "name": organization["name"],
        },
    }


@app.post("/api/auth/login")
def login(
    request: Request,
    data: LoginInput,
    database: Database = Depends(get_database),
):
    network_key = (
        email_key(f"network:{request.client.host}")
        if request.client
        else None
    )
    rate = enforce_login_rate_limit(database, data.email, network_key)
    user = database.users.find_one({"email": data.email, "status": "active"})
    if not user or not verify_password(user.get("password_hash", ""), data.password):
        for key, threshold in rate["keys"]:
            record_failed_login(database, key, threshold)
        record_security_event(
            database,
            organization_id=None,
            action="auth.login_failed",
            outcome="denied",
            actor="",
            severity="medium",
        )
        raise HTTPException(401, "Email or password is incorrect.")
    query: dict[str, Any] = {"user_id": user["user_id"], "status": "active"}
    if data.organization_id:
        query["organization_id"] = data.organization_id
    membership = database.memberships.find_one(query)
    if not membership:
        raise HTTPException(403, "No active membership exists for this organization.")
    for key, _threshold in rate["keys"]:
        database.login_attempts.delete_one({"key": key})
    token, expires = issue_session(database, user, membership["organization_id"])
    record_security_event(
        database,
        organization_id=membership["organization_id"],
        action="auth.login",
        outcome="success",
        actor=user["user_id"],
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires.isoformat(),
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "role": membership["role"],
        },
        "organization": database.organizations.find_one(
            {"organization_id": membership["organization_id"]},
            {"_id": 0, "organization_id": 1, "name": 1},
        ),
    }


@app.get("/api/auth/me")
def who_am_i(
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    organization = database.organizations.find_one(
        {"organization_id": principal["organization_id"]},
        {"_id": 0, "organization_id": 1, "name": 1},
    )
    return {"user": principal, "organization": organization}


@app.post("/api/auth/logout")
def logout(
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    database.sessions.update_one(
        {"session_id": principal["session_id"], "revoked_at": None},
        {"$set": {"revoked_at": utc_now()}},
    )
    record_event(database, principal, "auth.logout", "session", principal["session_id"])
    return {"status": "signed_out"}


@app.post("/api/auth/invitations/accept")
def accept_invitation(
    data: AcceptInvitationInput,
    database: Database = Depends(get_database),
):
    token_hash = hashlib.sha256(data.invitation_token.encode("utf-8")).hexdigest()
    invitation = database.invitations.find_one(
        {
            "token_hash": token_hash,
            "status": "pending",
            "expires_at": {"$gt": utc_now()},
        }
    )
    if not invitation:
        raise HTTPException(400, "This invitation is invalid or has expired.")
    user = database.users.find_one({"email": invitation["email"], "status": "active"})
    if user:
        if not verify_password(user.get("password_hash", ""), data.password):
            raise HTTPException(401, "Email or password is incorrect.")
    else:
        user = {
            "user_id": uuid_str(),
            "email": invitation["email"],
            "password_hash": hash_password(data.password),
            "status": "active",
            "created_at": now(),
        }
        try:
            database.users.insert_one(user)
        except Exception as exc:
            logger.error("Invited account creation failed: %s", type(exc).__name__)
            raise HTTPException(409, "This invitation could not create the account.") from exc
    try:
        database.memberships.insert_one(
            {
                "user_id": user["user_id"],
                "organization_id": invitation["organization_id"],
                "role": invitation["role"],
                "status": "active",
                "created_at": now(),
            }
        )
    except Exception as exc:
        raise HTTPException(409, "This account is already a member of the organization.") from exc
    database.invitations.update_one(
        {"token_hash": token_hash, "status": "pending"},
        {"$set": {"status": "accepted", "accepted_at": now()}},
    )
    token, expires = issue_session(database, user, invitation["organization_id"])
    record_security_event(
        database,
        organization_id=invitation["organization_id"],
        action="auth.invitation_accepted",
        outcome="success",
        actor=user["user_id"],
    )
    organization = database.organizations.find_one(
        {"organization_id": invitation["organization_id"]},
        {"_id": 0, "organization_id": 1, "name": 1},
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires.isoformat(),
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "role": invitation["role"],
        },
        "organization": organization,
    }


@app.post("/api/org/users")
def invite_user(
    data: InviteInput,
    principal: dict[str, Any] = Depends(require_roles("admin")),
    database: Database = Depends(get_database),
):
    invitation_token = secrets.token_urlsafe(32)
    database.invitations.insert_one(
        {
            "token_hash": hashlib.sha256(invitation_token.encode("utf-8")).hexdigest(),
            "email": data.email,
            "organization_id": principal["organization_id"],
            "role": data.role,
            "status": "pending",
            "created_at": now(),
            "expires_at": utc_now() + timedelta(days=7),
        }
    )
    record_event(
        database,
        principal,
        "permission.invitation_created",
        "membership",
        outcome="success",
    )
    return {
        "email": data.email,
        "role": data.role,
        "invitation_token": invitation_token,
        "expires_in_days": 7,
    }


@app.patch("/api/org/users/{user_id}")
def update_membership(
    user_id: str,
    data: MembershipUpdate,
    principal: dict[str, Any] = Depends(require_roles("admin")),
    database: Database = Depends(get_database),
):
    changes = data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, "Provide a role or membership status.")
    query = org_filter(principal, user_id=user_id, status="active")
    membership = database.memberships.find_one(query)
    if membership is None:
        raise HTTPException(404, "Active membership was not found.")
    if membership["role"] == "admin" and (
        changes.get("role", "admin") != "admin"
        or changes.get("status", "active") != "active"
    ):
        admins = database.memberships.count_documents(
            org_filter(principal, role="admin", status="active")
        )
        if admins <= 1:
            raise HTTPException(409, "The organization must retain at least one active Admin.")
    database.memberships.update_one(query, {"$set": changes})
    record_event(
        database,
        principal,
        "permission.membership_updated",
        "membership",
        user_id,
        metadata={"changed_fields": sorted(changes)},
    )
    return {"user_id": user_id, **changes}


@app.get("/api/org/users")
def list_users(
    principal: dict[str, Any] = Depends(require_roles("admin", "manager")),
    database: Database = Depends(get_database),
):
    memberships = list(
        database.memberships.find(
            org_filter(principal, status="active"), {"_id": 0}
        ).sort("created_at", ASCENDING)
    )
    user_ids = [entry["user_id"] for entry in memberships]
    users = {
        item["user_id"]: item
        for item in database.users.find(
            {"user_id": {"$in": user_ids}}, {"_id": 0, "user_id": 1, "email": 1}
        )
    }
    return {
        "members": [
            {
                "user_id": membership["user_id"],
                "email": users.get(membership["user_id"], {}).get("email"),
                "role": membership["role"],
                "status": membership["status"],
                "created_at": membership["created_at"],
            }
            for membership in memberships
        ]
    }


@app.get("/api/memories")
def list_memories(
    q: str = "",
    status: str = "All",
    limit: int = 250,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    if status != "All" and status not in STATUSES:
        raise HTTPException(400, "Invalid verification status.")
    query: dict[str, Any] = org_filter(principal)
    if status != "All":
        query["status"] = status
    if q.strip():
        safe_term = re.escape(q.strip())
        alternatives = [
            {"title": {"$regex": safe_term, "$options": "i"}},
            {"project": {"$regex": safe_term, "$options": "i"}},
            {"source": {"$regex": safe_term, "$options": "i"}},
            {"tags": {"$regex": safe_term, "$options": "i"}},
        ]
        alternatives.append({"content": {"$regex": safe_term, "$options": "i"}})
        alternatives.append({"search_tokens": {"$all": query_search_tokens(q)}})
        query["$or"] = alternatives
    records = database.memories.find(query, {"_id": 0}).sort(
        "updated_at", DESCENDING
    ).limit(max(1, min(limit, 250)))
    memories = [memory_out(record) for record in records]
    record_event(
        database,
        principal,
        "memory.search",
        "memory",
        outcome="success",
        metadata={"query_length": min(len(q), 200), "result_count": len(memories)},
    )
    return {"memories": memories}


@app.post("/api/memories")
def create_memory(
    data: MemoryInput,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    if data.supersedes_id:
        raise HTTPException(
            400,
            "supersedes_id is not supported by /api/memories; submit a correction request to /api/corrections.",
        )
    if data.status not in STATUSES:
        raise HTTPException(400, "Invalid verification status.")
    if principal["role"] == "employee" and data.status not in {"Unverified", "Disputed"}:
        raise HTTPException(403, "Employees can create only unverified or disputed memories.")
    stamp = now()
    sensitivity = classify_sensitivity(data.sensitivity, data.content)
    memory = {
        **data.model_dump(exclude={"supersedes_id"}),
        "id": uuid_str(),
        "organization_id": principal["organization_id"],
        "sensitivity": sensitivity,
        "version": 1,
        "created_at": stamp,
        "updated_at": stamp,
        "supersedes_id": None,
    }
    memory.update(secure_content_fields(data.content, sensitivity))
    try:
        database.memories.insert_one(memory)
    except Exception as exc:
        logger.error("Memory save failed: %s", type(exc).__name__)
        raise HTTPException(503, "Could not save the memory.") from exc
    record_event(database, principal, "memory.created", "memory", memory["id"])
    return {"memory": memory_out(memory)}


@app.patch("/api/memories/{memory_id}")
def update_memory(
    memory_id: str,
    data: MemoryUpdate,
    principal: dict[str, Any] = Depends(require_roles("admin", "manager")),
    database: Database = Depends(get_database),
):
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(422, "Provide at least one memory field to update.")
    if "status" in updates and updates["status"] not in STATUSES:
        raise HTTPException(422, "Invalid verification status.")
    if "sensitivity" in updates:
        updates["sensitivity"] = updates["sensitivity"].upper()
        if updates["sensitivity"] not in SENSITIVITY_LEVELS:
            raise HTTPException(422, "Invalid sensitivity level.")
    current = database.memories.find_one(org_filter(principal, id=memory_id))
    if current is None:
        raise HTTPException(404, "Memory was not found.")
    current_content = readable_content(current)
    new_content = updates.pop("content", current_content)
    requested_sensitivity = updates.get(
        "sensitivity", current.get("sensitivity", "INTERNAL")
    )
    sensitivity = classify_sensitivity(
        requested_sensitivity,
        new_content,
    )
    updates["sensitivity"] = sensitivity
    updates.update(secure_content_fields(new_content, sensitivity))
    updates["updated_at"] = now()
    unset: dict[str, str] = {}
    if "content_envelope" not in updates:
        unset["content_envelope"] = ""
        unset["search_tokens"] = ""
    result = database.memories.update_one(
        org_filter(principal, id=memory_id),
        {"$set": updates, **({"$unset": unset} if unset else {})},
    )
    if result.matched_count != 1:
        raise HTTPException(404, "Memory was not found.")
    record_event(
        database,
        principal,
        "memory.updated",
        "memory",
        memory_id,
        metadata={"changed_fields": sorted(updates.keys())},
    )
    memory = database.memories.find_one(
        org_filter(principal, id=memory_id), {"_id": 0}
    )
    return {"memory": memory_out(memory)}


@app.post("/api/memories/{memory_id}/archive")
def archive_memory(
    memory_id: str,
    principal: dict[str, Any] = Depends(require_roles("admin", "manager")),
    database: Database = Depends(get_database),
):
    result = database.memories.update_one(
        org_filter(principal, id=memory_id, status={"$ne": "Archived"}),
        {"$set": {"status": "Archived", "updated_at": now()}},
    )
    if result.matched_count != 1:
        raise HTTPException(404, "Memory was not found or is already archived.")
    record_event(database, principal, "memory.archived", "memory", memory_id)
    return {"status": "archived"}


@app.delete("/api/memories/{memory_id}")
def delete_memory(
    memory_id: str,
    principal: dict[str, Any] = Depends(require_roles("admin")),
    database: Database = Depends(get_database),
):
    memory = database.memories.find_one(org_filter(principal, id=memory_id))
    if memory is None:
        raise HTTPException(404, "Memory was not found.")
    database.memories.delete_one(org_filter(principal, id=memory_id))
    record_event(
        database,
        principal,
        "memory.deleted",
        "memory",
        memory_id,
        metadata={"title": memory["title"]},
        severity="medium",
    )
    return {"status": "deleted"}


@app.post("/api/corrections")
def submit_correction(
    data: CorrectionInput,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    memory = database.memories.find_one(
        org_filter(principal, id=data.memory_id), {"_id": 0}
    )
    if memory is None:
        raise HTTPException(404, "Memory for correction was not found.")
    if memory["status"] in {"Superseded", "Archived"}:
        raise HTTPException(409, "Only current accessible memories can be corrected.")
    if data.requested_status is not None and data.requested_status not in STATUSES:
        raise HTTPException(400, "Invalid requested verification status.")
    stamp = now()
    correction = {
        "id": uuid_str(),
        "organization_id": principal["organization_id"],
        "memory_id": memory["id"],
        "project": memory["project"],
        "supersedes_title": memory["title"],
        "status": "pending",
        "requested_status": data.requested_status or memory["status"],
        "title": data.title or memory["title"],
        "memory_type": data.memory_type or memory["memory_type"],
        "sensitivity": classify_sensitivity(
            memory.get("sensitivity", "INTERNAL"), data.content
        ),
        "source": data.source or memory["source"],
        "reviewer": None,
        "review_note": "",
        "approved_memory_id": None,
        "created_at": stamp,
        "reviewed_at": None,
    }
    correction.update(secure_content_fields(data.content, correction["sensitivity"]))
    database.corrections.insert_one(correction)
    record_event(database, principal, "correction.submitted", "correction", correction["id"])
    return {"correction": correction_out(correction, memory)}


@app.get("/api/corrections")
def list_corrections(
    status: str = "All",
    limit: int = 250,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    if status not in {"All", "pending", "approved", "rejected"}:
        raise HTTPException(400, "Invalid correction status.")
    query = org_filter(principal)
    if status != "All":
        query["status"] = status
    records = list(
        database.corrections.find(query, {"_id": 0})
        .sort("created_at", DESCENDING)
        .limit(max(1, min(limit, 250)))
    )
    memories = {
        item["id"]: item
        for item in database.memories.find(
            org_filter(
                principal,
                id={"$in": [item["memory_id"] for item in records]},
            ),
            {"_id": 0},
        )
    }
    return {
        "corrections": [
            correction_out(item, memories.get(item["memory_id"])) for item in records
        ]
    }


@app.post("/api/corrections/{correction_id}/review")
def review_correction(
    correction_id: str,
    data: CorrectionReviewInput,
    principal: dict[str, Any] = Depends(require_roles("admin", "manager")),
    database: Database = Depends(get_database),
):
    correction = database.corrections.find_one(
        org_filter(principal, id=correction_id), {"_id": 0}
    )
    if correction is None:
        raise HTTPException(404, "Correction request was not found.")
    if correction["status"] != "pending":
        raise HTTPException(409, "Correction request has already been reviewed.")
    old = database.memories.find_one(
        org_filter(principal, id=correction["memory_id"]), {"_id": 0}
    )
    if old is None:
        raise HTTPException(404, "Memory for correction was not found.")
    stamp = now()
    approved_memory = None
    if data.decision == "approved":
        if old["status"] in {"Superseded", "Archived"}:
            raise HTTPException(409, "The original memory is no longer current.")
        approved_memory = {
            "id": uuid_str(),
            "organization_id": principal["organization_id"],
            "title": correction["title"],
            "memory_type": correction["memory_type"],
            "project": old["project"],
            "status": correction["requested_status"] or old["status"],
            "content": readable_content(correction),
            "source": correction["source"],
            "version": old["version"] + 1,
            "created_at": stamp,
            "updated_at": stamp,
            "supersedes_id": old["id"],
            "sensitivity": correction.get("sensitivity", old.get("sensitivity", "INTERNAL")),
            "tags": old.get("tags", []),
        }
        approved_memory.update(
            secure_content_fields(
                approved_memory["content"], approved_memory["sensitivity"]
            )
        )
        changed = database.memories.update_one(
            org_filter(
                principal,
                id=old["id"],
                status={"$nin": ["Superseded", "Archived"]},
            ),
            {"$set": {"status": "Superseded", "updated_at": stamp}},
        )
        if changed.matched_count != 1:
            raise HTTPException(409, "The original memory changed during review.")
        database.memories.insert_one(approved_memory)
        record_event(
            database,
            principal,
            "memory.corrected",
            "memory",
            approved_memory["id"],
        )
    reviewer = principal["email"]
    result = database.corrections.update_one(
        org_filter(principal, id=correction_id, status="pending"),
        {
            "$set": {
                "status": data.decision,
                "reviewer": reviewer,
                "review_note": data.note,
                "approved_memory_id": approved_memory["id"] if approved_memory else None,
                "reviewed_at": stamp,
            }
        },
    )
    if result.matched_count != 1:
        raise HTTPException(409, "Correction request changed during review.")
    record_event(
        database,
        principal,
        f"correction.{data.decision}",
        "correction",
        correction_id,
    )
    corrected = {
        **correction,
        "status": data.decision,
        "reviewer": reviewer,
        "note": data.note,
        "review_note": data.note,
        "approved_memory_id": approved_memory["id"] if approved_memory else None,
        "reviewed_at": stamp,
    }
    return {
        "correction": correction_out(corrected, old),
        "memory": memory_out(approved_memory) if approved_memory else None,
    }


@app.get("/api/memories/{memory_id}/history")
def memory_history(
    memory_id: str,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    start = database.memories.find_one(
        org_filter(principal, id=memory_id), {"_id": 0}
    )
    if start is None:
        raise HTTPException(404, "Memory was not found.")
    pending = [start]
    seen: set[str] = set()
    history = []
    while pending:
        current = pending.pop()
        if current["id"] in seen:
            continue
        seen.add(current["id"])
        history.append(memory_out(current))
        parent_id = current.get("supersedes_id")
        if parent_id:
            parent = database.memories.find_one(
                org_filter(principal, id=parent_id), {"_id": 0}
            )
            if parent:
                pending.append(parent)
        pending.extend(
            database.memories.find(
                org_filter(principal, supersedes_id=current["id"]), {"_id": 0}
            )
        )
    history.sort(key=lambda item: (item["version"], item["created_at"], item["id"]))
    record_event(database, principal, "memory.history_accessed", "memory", memory_id)
    return {"versions": history}


@app.get("/api/sources/{memory_id}")
def get_source_preview(
    memory_id: str,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    memory = database.memories.find_one(org_filter(principal, id=memory_id))
    if memory is None:
        raise HTTPException(404, "Memory source was not found.")
    record_event(database, principal, "memory.evidence_accessed", "memory", memory_id)
    return {
        **memory_out(memory),
        "evidence_type": "memory-backed excerpt",
        "is_original_file": False,
    }


@app.get("/api/sources/demo/denied")
def demo_only_forbidden_source_preview(
    _principal: dict[str, Any] = Depends(current_principal),
):
    raise HTTPException(
        403,
        "Demo-only access-denial scenario; use organization membership for actual authorization.",
    )


@app.get("/api/handover")
def project_handover(
    project: str,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    project = project.strip()
    if not project:
        raise HTTPException(400, "A project name is required.")
    rows = database.memories.find(
        org_filter(
            principal,
            project={"$regex": f"^{re.escape(project)}$", "$options": "i"},
            status={"$in": ["Verified", "Unverified", "Disputed"]},
        )
    ).sort([("status", ASCENDING), ("updated_at", DESCENDING), ("id", ASCENDING)])
    memories = [memory_out(row) for row in rows]
    evidence = [
        f"- [{memory['status']}] {memory['title']} — {memory['content']} "
        f"(source: {memory['source']}; memory ID: {memory['id']})"
        for memory in memories
    ]
    missing_notice = (
        "No accessible memory records were found for this project; evidence is missing."
        if not memories
        else (
            "No verified evidence is available for this project."
            if not any(memory["status"] == "Verified" for memory in memories)
            else "Unverified or disputed records remain hypotheses and need confirmation."
        )
    )
    content = (
        f"Project handover: {project}\n\n"
        + (
            "Evidence from accessible memory records:\n" + "\n".join(evidence)
            if evidence
            else "Evidence: none."
        )
        + f"\n\nEvidence notice: {missing_notice}"
    )
    record_event(database, principal, "memory.handover_generated", "project")
    return {
        "project": project,
        "records": memories,
        "summary": content,
        "missing_evidence": missing_notice,
    }


def retrieve_memories(
    database: Database, principal: dict[str, Any], question: str
) -> list[dict[str, Any]]:
    words = [
        re.escape(word)
        for word in re.findall(r"[a-zA-Z0-9]+", question.lower())
        if len(word) > 3
    ]
    query: dict[str, Any] = org_filter(
        principal, status={"$in": ["Verified", "Unverified"]}
    )
    query_tokens = query_search_tokens(question)
    if words:
        query["$or"] = [
            {field: {"$regex": "|".join(words), "$options": "i"}}
            for field in ("title", "content", "project", "source", "tags")
        ]
        if query_tokens:
            query["$or"].append(            {"search_tokens": {"$all": query_tokens}})
    found = list(database.memories.find(query, {"_id": 0}).limit(250))
    found = [memory_out(row) for row in found]
    found.sort(
        key=lambda row: (
            sum(
                1
                for word in words
                if re.search(word, f"{row['title']} {row['content']} {row['project']} {row['source']}", re.I)
            ),
            row["status"] == "Verified",
        ),
        reverse=True,
    )
    return found[:4]


@app.post("/api/privacy/preview")
def preview_privacy(
    data: PrivacyPreviewInput,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    memories = []
    if data.memory_ids:
        memories = list(
            database.memories.find(
                org_filter(principal, id={"$in": data.memory_ids}), {"_id": 0}
            )
        )
        if len(memories) != len(set(data.memory_ids)):
            raise HTTPException(404, "One or more memories were not found in your organization.")
        memories = [memory_out(memory) for memory in memories]
    else:
        memories = retrieve_memories(database, principal, data.question)
    decision = privacy_decision(data.question, memories)
    record_event(
        database,
        principal,
        f"privacy.{decision['decision']}",
        "ai_gateway",
        outcome=decision["decision"],
        severity="high" if decision["decision"] == "blocked" else "info",
        metadata={
            "categories": decision["categories"],
            "redacted_categories": decision["redacted_categories"],
            "memory_count": decision["memory_count"],
            "provider": "none",
            "model": "none",
        },
    )
    return decision


@app.post("/api/agent/chat")
def chat(
    data: AskInput,
    principal: dict[str, Any] = Depends(current_principal),
    database: Database = Depends(get_database),
):
    refs = retrieve_memories(database, principal, data.question)
    decision = privacy_decision(data.question, refs)
    record_event(
        database,
        principal,
        f"privacy.{decision['decision']}",
        "ai_gateway",
        outcome=decision["decision"],
        severity="high" if decision["decision"] == "blocked" else "info",
        metadata={
            "categories": decision["categories"],
            "redacted_categories": decision["redacted_categories"],
            "memory_count": decision["memory_count"],
            "provider": "none",
            "model": "none",
        },
    )
    if decision["decision"] == "blocked":
        raise HTTPException(403, decision["reason"])
    record_event(
        database,
        principal,
        "memory.search",
        "query",
        outcome="success",
        metadata={"query_length": len(data.question), "result_count": len(refs)},
    )
    if not refs:
        return {
            "answer": "I could not find enough matching evidence in the accessible memory records. Try naming a project or incident.",
            "sources": [],
            "mode": "keyword-demo",
            "trace": [
                "query received",
                "organization-scoped keyword retrieval",
                "no matching evidence found",
                "no external provider configured; no data transmitted",
            ],
            "privacy": {key: value for key, value in decision.items() if key != "preview"},
        }
    is_payment = any(
        word in data.question.lower()
        for word in ("payment", "timeout", "incident", "resolve", "fix")
    )
    answer = (
        "The earlier connection-pool mitigation is historical and has been superseded. The current verified guidance is to investigate queue consumer saturation, retry amplification, and downstream latency in the queue-backed architecture, then validate changes against current telemetry. Queue saturation remains unverified until evidence confirms it."
        if is_payment
        else "The closest stored records are attached below. Treat unverified claims as hypotheses and inspect their source documents before acting."
    )
    return {
        "answer": answer,
        "sources": refs,
        "mode": "keyword-demo",
        "trace": [
            "query received",
            "organization-scoped keyword retrieval",
            "privacy policy evaluated",
            "bounded evidence returned",
            "no external provider configured; no data transmitted",
        ],
        "privacy": {key: value for key, value in decision.items() if key != "preview"},
    }


def audit_filter(q: str, action: str, org_id: str) -> dict[str, Any]:
    query: dict[str, Any] = {"organization_id": org_id}
    if action == "memory":
        query["action"] = {
            "$in": [
                "memory.created",
                "memory.corrected",
                "memory.updated",
                "memory.archived",
                "memory.deleted",
                "correction.submitted",
                "correction.approved",
                "correction.rejected",
            ]
        }
    elif action == "correction":
        query["action"] = {
            "$in": [
                "correction.submitted",
                "correction.approved",
                "correction.rejected",
            ]
        }
    elif action != "All":
        query["action"] = action
    if q.strip():
        term = re.escape(q.strip())
        query["$or"] = [
            {"actor": {"$regex": term, "$options": "i"}},
            {"action": {"$regex": term, "$options": "i"}},
            {"resource_type": {"$regex": term, "$options": "i"}},
            {"resource_id": {"$regex": term, "$options": "i"}},
            {"outcome": {"$regex": term, "$options": "i"}},
        ]
    return query


@app.get("/api/audit")
def list_audit(
    q: str = "",
    action: str = "All",
    limit: int = 500,
    principal: dict[str, Any] = Depends(require_roles("admin", "manager")),
    database: Database = Depends(get_database),
):
    query = audit_filter(q, action, principal["organization_id"])
    max_limit = max(1, min(limit, 500))
    events = list(
        database.audit_logs.find(query, {"_id": 0})
        .sort([("created_at", DESCENDING), ("seq", DESCENDING)])
        .limit(max_limit)
    )
    total = database.audit_logs.count_documents(query)
    return {
        "events": events,
        "total": total,
        "limit": max_limit,
        "actions": sorted(
            database.audit_logs.distinct(
                "action", {"organization_id": principal["organization_id"]}
            )
        ),
    }


@app.get("/api/audit/export")
def export_audit(
    q: str = "",
    action: str = "All",
    principal: dict[str, Any] = Depends(require_roles("admin", "manager")),
    database: Database = Depends(get_database),
):
    query = audit_filter(q, action, principal["organization_id"])
    columns = (
        "created_at",
        "actor",
        "action",
        "resource_type",
        "resource_id",
        "outcome",
        "severity",
    )

    def generate_csv():
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\r\n")
        writer.writerow(columns)
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        for row in database.audit_logs.find(query, {"_id": 0}).sort(
            [("created_at", DESCENDING), ("seq", DESCENDING)]
        ):
            cells = [str(row.get(column) or "") for column in columns]
            cells = [
                f"'{value}"
                if value.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}
                else value
                for value in cells
            ]
            writer.writerow(cells)
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    record_event(database, principal, "audit.exported", "audit_log")
    return StreamingResponse(
        generate_csv(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="smriti-nexus-audit.csv"',
            "Cache-Control": "no-store",
        },
    )


@app.get("/api/security/overview")
def security_overview(
    principal: dict[str, Any] = Depends(require_roles("admin")),
    database: Database = Depends(get_database),
):
    events = list(
        database.audit_logs.find(
            org_filter(
                principal,
                action={
                    "$in": [
                        "auth.login",
                        "auth.logout",
                        "auth.login_failed",
                        "auth.rate_limited",
                        "privacy.allowed",
                        "privacy.redacted",
                        "privacy.blocked",
                        "memory.created",
                        "memory.updated",
                        "memory.archived",
                        "memory.deleted",
                        "permission.member_added",
                    ]
                },
            ),
            {
                "_id": 0,
                "seq": 1,
                "actor": 1,
                "action": 1,
                "resource_type": 1,
                "resource_id": 1,
                "outcome": 1,
                "severity": 1,
                "created_at": 1,
                "metadata": 1,
            },
        )
        .sort("created_at", DESCENDING)
        .limit(100)
    )
    day_ago = utc_now() - timedelta(hours=24)
    settings = {
        "database": "mongodb-atlas" if os.getenv("MONGODB_URI", "").startswith("mongodb+srv://") else "mongodb",
        "https_expected": os.getenv("ENVIRONMENT", "development").lower() == "production",
        "external_ai_provider": "not configured",
        "managed_kms": (
            "Local development key"
            if local_master_key_configured()
            else
            "Google Cloud KMS configured; access not verified"
            if os.getenv("KMS_PROVIDER", "").lower() == "google-cloud-kms"
            and os.getenv("GCP_KMS_KEY_NAME")
            else "not configured"
        ),
        "field_level_encryption": (
            "Local development key"
            if local_master_key_configured()
            else
            "Google Cloud KMS envelope encryption configured; access not verified"
            if os.getenv("KMS_PROVIDER", "").lower() == "google-cloud-kms"
            and os.getenv("GCP_KMS_KEY_NAME")
            else "development-only AES-GCM active"
            if os.getenv("ENVIRONMENT", "development").lower() != "production"
            and os.getenv("DEV_FIELD_ENCRYPTION_KEY")
            else "not configured"
        ),
    }
    alerts = {
        "failed_logins_last_24h": database.global_security_events.count_documents(
            {
                "action": "auth.login_failed",
                "created_at": {"$gte": day_ago},
            }
        ),
        "rate_limits_last_24h": database.global_security_events.count_documents(
            {
                "action": "auth.rate_limited",
                "created_at": {"$gte": day_ago},
            }
        ),
    }
    return {"events": events, "configuration": settings, "alerts": alerts}


@app.get("/api/security/audit-integrity")
def audit_integrity(
    principal: dict[str, Any] = Depends(require_roles("admin")),
    database: Database = Depends(get_database),
):
    events = list(
        database.audit_logs.find(
            {"organization_id": principal["organization_id"]},
            {"_id": 0},
        ).sort("seq", ASCENDING)
    )
    intact = True
    previous = ""
    for event in events:
        if event.get("previous_hash", "") != previous or not verify_audit_hash(event):
            intact = False
            break
        previous = event.get("hash", "")
    return {"intact": intact, "checked_events": len(events)}
