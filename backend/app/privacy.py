from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import HTTPException
from pymongo.database import Database

SENSITIVITY_LEVELS = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "TOP_SECRET"}
_AUDIT_LOCK = threading.Lock()
_SECRET_PATTERNS = (
    ("credential", re.compile(r"(?i)\b(password|passwd|secret)\s*[:=]\s*[^\s,;]+")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)")),
    ("government_id", re.compile(r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b")),
)


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    redacted = text
    categories = []
    for category, pattern in _SECRET_PATTERNS:
        redacted, count = pattern.subn(f"[REDACTED:{category}]", redacted)
        if count:
            categories.append(category)
    return redacted, categories


def classify_sensitivity(requested: str, content: str) -> str:
    normalized = requested.upper()
    if normalized not in SENSITIVITY_LEVELS:
        raise HTTPException(422, "Invalid sensitivity classification.")
    _, detected = redact_sensitive(content)
    if {"credential", "api_key"} & set(detected):
        return "TOP_SECRET"
    if {"email", "phone", "government_id"} & set(detected):
        return "CONFIDENTIAL" if normalized in {"PUBLIC", "INTERNAL"} else normalized
    return normalized


def privacy_decision(
    question: str, memories: list[dict[str, Any]], max_memories: int = 3
) -> dict[str, Any]:
    levels = {
        str(memory.get("sensitivity", "INTERNAL")).upper()
        for memory in memories
    }
    invalid_levels = levels - SENSITIVITY_LEVELS
    if invalid_levels:
        raise HTTPException(422, "A memory has an invalid sensitivity classification.")
    if "TOP_SECRET" in levels:
        return {
            "decision": "blocked",
            "reason": "TOP_SECRET content cannot be sent to an external AI provider.",
            "categories": sorted(levels),
            "redacted_categories": [],
            "memory_count": len(memories),
            "preview": [],
        }
    safe_question, question_categories = redact_sensitive(question)
    selected = memories[:max_memories]
    preview = []
    redacted_categories = set(question_categories)
    for memory in selected:
        safe_content, found = redact_sensitive(
            f"{memory.get('title', '')}\n{memory.get('content', '')}"
        )
        redacted_categories.update(found)
        preview.append(
            {
                "memory_id": memory.get("id"),
                "title": safe_content.split("\n", 1)[0],
                "excerpt": safe_content.split("\n", 1)[-1][:500],
                "sensitivity": str(memory.get("sensitivity", "INTERNAL")).upper(),
            }
        )
    return {
        "decision": "redacted" if redacted_categories else "allowed",
        "reason": (
            "Sensitive identifiers were redacted before any external AI request."
            if redacted_categories
            else "Context is minimized to at most three authorized memories."
        ),
        "categories": sorted(levels or {"INTERNAL"}),
        "redacted_categories": sorted(redacted_categories),
        "memory_count": len(selected),
        "safe_question": safe_question,
        "preview": preview,
    }


def safe_audit_key() -> bytes:
    configured = os.getenv("AUDIT_SIGNING_KEY") or os.getenv("JWT_SECRET")
    if configured:
        return configured.encode("utf-8")
    return b"development-only-audit-key-not-for-production"


def record_audit(
    database: Database,
    *,
    organization_id: str,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    outcome: str = "recorded",
    severity: str = "info",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with _AUDIT_LOCK:
        now = datetime.now(timezone.utc)
        counter = database.audit_counters.find_one_and_update(
            {"organization_id": organization_id},
            {"$inc": {"seq": 1}, "$setOnInsert": {"organization_id": organization_id}},
            upsert=True,
            return_document=True,
        )
        sequence = int((counter or {}).get("seq", 1))
        previous = database.audit_logs.find_one(
            {"organization_id": organization_id, "seq": sequence - 1},
            {"hash": 1},
        )
        event = {
            "id": str(uuid4()),
            "organization_id": organization_id,
            "seq": sequence,
            "actor": actor,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "severity": severity,
            "created_at": now.isoformat(),
            "metadata": metadata or {},
            "previous_hash": previous.get("hash", "") if previous else "",
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        event["hash"] = hmac.new(
            safe_audit_key(), canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        database.audit_logs.insert_one(event)
        return event


def record_security_event(
    database: Database,
    *,
    organization_id: str | None,
    action: str,
    outcome: str,
    actor: str,
    severity: str = "info",
) -> None:
    if organization_id:
        record_audit(
            database,
            organization_id=organization_id,
            actor=actor,
            action=action,
            resource_type="authentication",
            outcome=outcome,
            severity=severity,
        )
    else:
        database.global_security_events.insert_one(
            {
                "action": action,
                "outcome": outcome,
                "severity": severity,
                "created_at": datetime.now(timezone.utc),
            }
        )


def verify_audit_hash(event: dict[str, Any]) -> bool:
    claimed_hash = event.get("hash", "")
    signed_fields = {key: value for key, value in event.items() if key != "hash"}
    canonical = json.dumps(signed_fields, sort_keys=True, separators=(",", ":"))
    expected_hash = hmac.new(
        safe_audit_key(), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(claimed_hash, expected_hash)
