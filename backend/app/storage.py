from __future__ import annotations

import os
from pymongo import MongoClient
from pymongo.database import Database


def create_database(uri: str | None = None) -> Database:
    mongo_uri = uri or os.getenv("MONGODB_URI")
    if not mongo_uri:
        raise RuntimeError("MONGODB_URI must be configured before the API can start.")
    client = MongoClient(
        mongo_uri,
        appname="SmritiNexus",
        serverSelectionTimeoutMS=8000,
        connectTimeoutMS=8000,
        retryWrites=True,
        tls=True,
        tz_aware=True,
    )
    client.admin.command("ping")
    database_name = os.getenv("MONGODB_DATABASE", "smriti_nexus")
    database = client[database_name]
    ensure_indexes(database)
    return database


def ensure_indexes(database: Database) -> None:
    database.organizations.create_index("slug", unique=True)
    database.users.create_index("email", unique=True)
    database.memberships.create_index(
        [("organization_id", 1), ("user_id", 1)], unique=True
    )
    database.memberships.create_index([("user_id", 1), ("status", 1)])
    database.sessions.create_index("expires_at", expireAfterSeconds=0)
    database.sessions.create_index([("user_id", 1), ("organization_id", 1)])
    database.invitations.create_index("token_hash", unique=True)
    database.invitations.create_index("expires_at", expireAfterSeconds=0)
    database.invitations.create_index([("organization_id", 1), ("email", 1)])
    database.login_attempts.create_index("key", unique=True)
    database.global_security_events.create_index("created_at")
    database.memories.create_index(
        [("organization_id", 1), ("updated_at", -1)]
    )
    database.memories.create_index(
        [("organization_id", 1), ("project", 1), ("status", 1)]
    )
    database.memories.create_index(
        [("organization_id", 1), ("status", 1), ("search_tokens", 1)]
    )
    database.memories.create_index(
        [("organization_id", 1), ("title", "text"), ("content", "text"), ("source", "text")]
    )
    database.corrections.create_index(
        [("organization_id", 1), ("status", 1), ("created_at", -1)]
    )
    database.audit_logs.create_index(
        [("organization_id", 1), ("created_at", -1)]
    )
    database.audit_logs.create_index(
        [("organization_id", 1), ("seq", 1)], unique=True
    )
    database.audit_counters.create_index("organization_id", unique=True)
