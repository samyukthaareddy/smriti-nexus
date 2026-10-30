from __future__ import annotations

from datetime import timedelta

import jwt
import mongomock
import pytest
from fastapi.testclient import TestClient

from app import main
from app.auth import jwt_secret, utc_now
from app import key_management
from app.storage import ensure_indexes


@pytest.fixture
def database():
    client = mongomock.MongoClient(tz_aware=True)
    db = client.smriti_test
    ensure_indexes(db)
    yield db
    client.close()


@pytest.fixture
def client(database, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("JWT_SECRET", "tests-only-secret-with-at-least-32-characters")
    monkeypatch.setenv("AUDIT_SIGNING_KEY", "tests-only-audit-secret-with-32-characters")
    monkeypatch.setenv("KMS_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_MASTER_KEY", "local-test-master-key-at-least-32-bytes")
    main.app.state.database = database
    with TestClient(main.app) as test_client:
        yield test_client
    main.app.state.database = None


def test_local_demo_mode_skips_login_but_rejects_remote_client(
    database, monkeypatch
):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DEMO_MODE", "true")
    main.app.state.database = database
    try:
        with TestClient(main.app, client=("127.0.0.1", 12345)) as local_client:
            memories = local_client.get("/api/memories")
            assert memories.status_code == 200, memories.text
            assert "Payment timeout incident" in {
                item["title"] for item in memories.json()["memories"]
            }
            added = local_client.post(
                "/api/memories",
                json={
                    "title": "Local demo write",
                    "content": "Saved without signing in.",
                    "status": "Unverified",
                },
            )
            assert added.status_code == 200, added.text

        with TestClient(main.app, client=("203.0.113.10", 12345)) as remote_client:
            assert remote_client.get("/api/memories").status_code == 403
    finally:
        main.app.state.database = None


def test_demo_mode_starts_with_ephemeral_database_without_mongodb(
    monkeypatch,
):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("MONGODB_URI", "mongodb://invalid-host-for-local-demo")
    main.app.state.database = None
    try:
        with TestClient(main.app, client=("127.0.0.1", 12345)) as local_client:
            assert local_client.get("/api/health").json() == {
                "status": "ok",
                "database": "local-demo",
            }
            result = local_client.get("/api/memories")
            assert result.status_code == 200, result.text
            assert "Payment timeout incident" in {
                item["title"] for item in result.json()["memories"]
            }
    finally:
        main.app.state.database = None


def test_production_rejects_demo_mode(database, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("JWT_SECRET", "tests-only-secret-with-at-least-32-characters")
    main.app.state.database = database
    try:
        with pytest.raises(RuntimeError, match="DEMO_MODE"):
            with TestClient(main.app):
                pass
    finally:
        main.app.state.database = None


def test_google_cloud_kms_envelope_round_trip_and_api_use(
    client, database, monkeypatch
):
    class FakeKMSClient:
        def __init__(self):
            self.encrypted = []

        def encrypt(self, request):
            assert request["name"] == (
                "projects/test-project/locations/global/"
                "keyRings/test-ring/cryptoKeys/test-key"
            )
            ciphertext = request["plaintext"][::-1]
            self.encrypted.append(ciphertext)
            return type("EncryptResponse", (), {"ciphertext": ciphertext})()

        def decrypt(self, request):
            assert request["name"] == (
                "projects/test-project/locations/global/"
                "keyRings/test-ring/cryptoKeys/test-key"
            )
            return type(
                "DecryptResponse",
                (),
                {"plaintext": request["ciphertext"][::-1]},
            )()

    fake_kms = FakeKMSClient()
    def make_fake_kms_client():
        return fake_kms

    monkeypatch.setattr(key_management, "google_kms_client", make_fake_kms_client)
    monkeypatch.setenv("KMS_PROVIDER", "google-cloud-kms")
    monkeypatch.setenv(
        "GCP_KMS_KEY_NAME",
        "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
    )
    monkeypatch.setenv("SEARCH_INDEX_KEY", "test-search-index-key-at-least-32-bytes")
    monkeypatch.delenv("LOCAL_MASTER_KEY", raising=False)
    signup(client)

    saved = memory(
        client,
        title="KMS protected record",
        content="Contact sensitive.person@example.test for the confidential case.",
        sensitivity="CONFIDENTIAL",
    )
    assert saved["content"].startswith("Contact sensitive.person@example.test")
    stored = database.memories.find_one({"id": saved["id"]})
    envelope = stored["content_envelope"]
    assert envelope["version"] == "2"
    assert envelope["wrapped_key"]["provider"] == "google-cloud-kms"
    assert envelope["wrapped_key"]["key_name"].endswith("/cryptoKeys/test-key")
    assert stored["search_tokens"]
    assert "sensitive.person@example.test" not in str(envelope)
    assert key_management.reveal_content(stored) == saved["content"]
    assert len(fake_kms.encrypted) == 1


def test_production_key_provider_requires_google_kms_config(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("KMS_PROVIDER", "google-cloud-kms")
    monkeypatch.setenv(
        "GCP_KMS_KEY_NAME",
        "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
    )
    monkeypatch.setenv("SEARCH_INDEX_KEY", "test-search-index-key-at-least-32-bytes")
    key_management.validate_production_key_provider()

    monkeypatch.delenv("SEARCH_INDEX_KEY")
    with pytest.raises(RuntimeError, match="SEARCH_INDEX_KEY"):
        key_management.validate_production_key_provider()
    monkeypatch.setenv("SEARCH_INDEX_KEY", "test-search-index-key-at-least-32-bytes")
    monkeypatch.setenv("GCP_KMS_KEY_NAME", "not-a-crypto-key-resource")
    with pytest.raises(RuntimeError, match="full Google Cloud KMS"):
        key_management.validate_production_key_provider()


def test_legacy_development_envelope_remains_readable(monkeypatch):
    import base64
    import secrets

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("KMS_PROVIDER", raising=False)
    monkeypatch.setenv(
        "DEV_FIELD_ENCRYPTION_KEY", "dev-only-test-key-with-32-characters"
    )
    provider = key_management.DevelopmentKeyProvider(
        "dev-only-test-key-with-32-characters"
    )
    data_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    plaintext = b"legacy confidential memory"
    envelope = {
        "version": "1",
        "key": base64.urlsafe_b64encode(
            provider.encrypt_data_key(data_key)
        ).decode("ascii"),
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(
            AESGCM(data_key).encrypt(nonce, plaintext, b"smriti-memory-v1")
        ).decode("ascii"),
    }
    encryptor = key_management.configured_encryptor()
    assert encryptor is not None
    assert encryptor.decrypt(envelope) == plaintext


def test_google_cloud_kms_errors_are_explicit():
    from google.api_core.exceptions import PermissionDenied

    class DeniedKMSClient:
        def encrypt(self, request):
            assert request["name"].endswith("/cryptoKeys/test-key")
            raise PermissionDenied("test denial")

        def decrypt(self, request):
            assert request["name"].endswith("/cryptoKeys/test-key")
            raise PermissionDenied("test denial")

    provider = key_management.GoogleCloudKMSProvider(
        "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
        client=DeniedKMSClient(),
    )
    with pytest.raises(RuntimeError, match="Check ADC credentials, IAM permissions"):
        provider.encrypt_data_key(b"example-data-key")


def signup(client, email="admin@example.test", organization="Test Workspace"):
    response = client.post(
        "/api/auth/signup",
        json={
            "email": email,
            "password": "correct-horse-battery-staple",
            "organization_name": organization,
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    client.headers.update({"Authorization": f"Bearer {result['access_token']}"})
    return result


def memory(client, **fields):
    response = client.post(
        "/api/memories",
        json={
            "title": fields.pop("title", "Test memory"),
            "content": fields.pop("content", "Evidence for this test"),
            "project": fields.pop("project", "Test project"),
            "status": fields.pop("status", "Verified"),
            "source": fields.pop("source", "test-evidence.md"),
            **fields,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["memory"]


def test_signup_login_bad_password_logout_and_protected_routes(client, database):
    assert client.get("/api/memories").status_code == 401
    result = signup(client)
    assert result["user"]["role"] == "admin"
    assert database.users.find_one({"email": "admin@example.test"})["password_hash"] != (
        "correct-horse-battery-staple"
    )
    assert database.users.find_one({"email": "admin@example.test"})["password_hash"].startswith(
        "$argon2id$"
    )
    assert client.get("/api/memories").status_code == 200

    bad_password = client.post(
        "/api/auth/login",
        json={"email": "admin@example.test", "password": "wrong-password"},
    )
    assert bad_password.status_code == 401

    login = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "correct-horse-battery-staple",
        },
    )
    assert login.status_code == 200
    client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
    assert client.get("/api/auth/me").json()["user"]["role"] == "admin"
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_signup_validation_duplicate_email_and_login_lockout(client, database):
    assert client.post(
        "/api/auth/signup",
        json={
            "email": "not-an-email",
            "password": "correct-horse-battery-staple",
            "organization_name": "Workspace",
        },
    ).status_code == 422
    signup(client)
    assert client.post(
        "/api/auth/signup",
        json={
            "email": "admin@example.test",
            "password": "correct-horse-battery-staple",
            "organization_name": "Duplicate",
        },
    ).status_code == 409
    client.headers.pop("Authorization", None)
    for _ in range(5):
        assert client.post(
            "/api/auth/login",
            json={"email": "lock@example.test", "password": "wrong-password"},
        ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={"email": "lock@example.test", "password": "wrong-password"},
    ).status_code == 429
    assert database.global_security_events.count_documents(
        {"action": "auth.login_failed"}
    ) == 5
    assert database.global_security_events.count_documents(
        {"action": "auth.rate_limited"}
    ) == 1


def test_expired_token_and_server_revocation(client, database):
    result = signup(client)
    user = database.users.find_one({"email": "admin@example.test"})
    expired_session = "expired-session"
    database.sessions.insert_one(
        {
            "session_id": expired_session,
            "user_id": user["user_id"],
            "organization_id": result["organization"]["organization_id"],
            "revoked_at": None,
            "expires_at": utc_now() + timedelta(minutes=1),
        }
    )
    expired = jwt.encode(
        {
            "sub": user["user_id"],
            "sid": expired_session,
            "org": result["organization"]["organization_id"],
            "iat": utc_now() - timedelta(hours=2),
            "exp": utc_now() - timedelta(hours=1),
            "iss": "smriti-nexus",
        },
        jwt_secret(),
        algorithm="HS256",
    )
    client.headers["Authorization"] = f"Bearer {expired}"
    assert client.get("/api/auth/me").status_code == 401
    client.headers["Authorization"] = f"Bearer {result['access_token']}"
    assert client.post("/api/auth/logout").status_code == 200
    client.headers["Authorization"] = f"Bearer {result['access_token']}"
    assert client.get("/api/auth/me").status_code == 401


def test_organization_isolation_for_memories_and_evidence(client, database):
    first = signup(client, "first@example.test", "First")
    first_memory = memory(client, title="Private first memory")
    client.headers.pop("Authorization", None)
    second = signup(client, "second@example.test", "Second")
    second_memory = memory(client, title="Private second memory")
    titles = {item["title"] for item in client.get("/api/memories").json()["memories"]}
    assert titles == {
        "Payment timeout incident",
        "Architecture migration changes retry behavior",
        "Rollback guardrail",
        "Queue saturation under burst traffic",
        "Connection-pool mitigation",
        "Private second memory",
    }
    assert client.get(f"/api/sources/{first_memory['id']}").status_code == 404
    assert client.get(f"/api/memories/{first_memory['id']}/history").status_code == 404
    assert first["organization"]["organization_id"] != second["organization"]["organization_id"]
    first_stored = database.memories.find_one({"id": first_memory["id"]})
    second_stored = database.memories.find_one({"id": second_memory["id"]})
    assert first_stored["organization_id"] == first["organization"]["organization_id"]
    assert second_stored["organization_id"] == second["organization"]["organization_id"]


def test_confidential_content_is_encrypted_and_searchable(client, database, monkeypatch):
    signup(client)
    monkeypatch.delenv("KMS_PROVIDER", raising=False)
    monkeypatch.delenv("LOCAL_MASTER_KEY", raising=False)
    monkeypatch.delenv("DEV_FIELD_ENCRYPTION_KEY", raising=False)
    rejected = client.post(
        "/api/memories",
        json={
            "title": "Must not persist without a key",
            "content": "Contact private@example.test for the confidential review.",
            "project": "Test project",
            "status": "Verified",
        },
    )
    assert rejected.status_code == 503
    assert database.memories.find_one(
        {"title": "Must not persist without a key"}
    ) is None

    monkeypatch.setenv("KMS_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_MASTER_KEY", "local-test-master-key-at-least-32-bytes")
    created = memory(
        client,
        title="Encrypted confidential memory",
        content="Contact private@example.test for the confidential review.",
    )
    assert created["sensitivity"] == "CONFIDENTIAL"
    assert created["content"] == "Contact private@example.test for the confidential review."
    stored = database.memories.find_one({"id": created["id"]})
    assert stored["content"] == ""
    assert stored["content_envelope"]["wrapped_key"]["provider"] == "local"
    assert "private@example.test" not in str(stored["content_envelope"])
    assert "confidential" not in str(stored["content_envelope"])
    matches = client.get("/api/memories", params={"q": "private@example.test"})
    assert matches.status_code == 200
    assert created["id"] in {
        item["id"] for item in matches.json()["memories"]
    }


def test_production_startup_rejects_development_encryption_key(
    database, monkeypatch
):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET", "tests-only-secret-with-at-least-32-characters")
    monkeypatch.setenv(
        "LOCAL_MASTER_KEY", "local-test-master-key-at-least-32-bytes"
    )
    main.app.state.database = database
    try:
        with pytest.raises(RuntimeError, match="development-only"):
            with TestClient(main.app):
                pass
    finally:
        main.app.state.database = None


def test_top_secret_correction_is_encrypted_through_review(client, database, monkeypatch):
    monkeypatch.setenv("KMS_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_MASTER_KEY", "local-test-master-key-at-least-32-bytes")
    signup(client)
    original = memory(client, title="Correction target")
    response = client.post(
        "/api/corrections",
        json={
            "memory_id": original["id"],
            "content": "password=not-a-real-password must never be shared.",
        },
    )
    assert response.status_code == 200, response.text
    correction = response.json()["correction"]
    assert correction["sensitivity"] == "TOP_SECRET"
    stored_correction = database.corrections.find_one({"id": correction["id"]})
    assert stored_correction["content"] == ""
    assert "not-a-real-password" not in str(stored_correction["content_envelope"])

    reviewed = client.post(
        f"/api/corrections/{correction['id']}/review",
        json={"decision": "approved"},
    )
    assert reviewed.status_code == 200, reviewed.text
    approved = database.memories.find_one(
        {"id": reviewed.json()["memory"]["id"]}
    )
    assert approved["sensitivity"] == "TOP_SECRET"
    assert approved["content"] == ""
    assert "not-a-real-password" not in str(approved["content_envelope"])


def test_roles_invitation_review_and_admin_protection(client, database):
    signup(client)
    original = memory(client, title="Correction target")
    correction = client.post(
        "/api/corrections",
        json={"memory_id": original["id"], "content": "Updated supporting evidence"},
    ).json()["correction"]
    invitation = client.post(
        "/api/org/users",
        json={"email": "employee@example.test", "role": "employee"},
    )
    assert invitation.status_code == 200
    invite_result = client.post(
        "/api/auth/invitations/accept",
        json={
            "invitation_token": invitation.json()["invitation_token"],
            "password": "employee-password-123",
        },
    )
    assert invite_result.status_code == 200
    client.headers["Authorization"] = f"Bearer {invite_result.json()['access_token']}"
    denied_review = client.post(
        f"/api/corrections/{correction['id']}/review",
        json={"decision": "approved", "reviewer": "spoofed@example.test"},
    )
    assert denied_review.status_code == 403
    denied_verified = client.post(
        "/api/memories",
        json={"title": "Not verified", "content": "Evidence", "status": "Verified"},
    )
    assert denied_verified.status_code == 403
    employee_memory = memory(client, title="Employee draft", status="Unverified")
    assert employee_memory["status"] == "Unverified"
    assert client.get("/api/security/overview").status_code == 403

    client.headers["Authorization"] = f"Bearer {invite_result.json()['access_token']}"
    client.headers.pop("Authorization", None)
    admin_login = client.post(
        "/api/auth/login",
        json={"email": "admin@example.test", "password": "correct-horse-battery-staple"},
    )
    client.headers["Authorization"] = f"Bearer {admin_login.json()['access_token']}"
    approved = client.post(
        f"/api/corrections/{correction['id']}/review",
        json={"decision": "approved", "reviewer": "spoofed@example.test"},
    )
    assert approved.status_code == 200
    assert approved.json()["correction"]["reviewer"] == "admin@example.test"
    assert client.patch(
        f"/api/org/users/{invite_result.json()['user']['user_id']}",
        json={"status": "revoked"},
    ).status_code == 200
    client.headers["Authorization"] = f"Bearer {invite_result.json()['access_token']}"
    assert client.get("/api/auth/me").status_code == 401
    assert database.audit_logs.find_one({"action": "permission.membership_updated"})


def test_memory_update_archive_delete_and_history(client):
    signup(client)
    original = memory(client, title="Editable memory", status="Unverified")
    updated = client.patch(
        f"/api/memories/{original['id']}",
        json={"title": "Updated title", "sensitivity": "CONFIDENTIAL", "tags": ["incident"]},
    )
    assert updated.status_code == 200
    assert updated.json()["memory"]["sensitivity"] == "CONFIDENTIAL"
    assert updated.json()["memory"]["tags"] == ["incident"]
    assert client.post(f"/api/memories/{original['id']}/archive").status_code == 200
    assert client.delete(f"/api/memories/{original['id']}").status_code == 200
    assert client.get(f"/api/memories/{original['id']}/history").status_code == 404
    assert client.delete("/api/memories/demo-1").status_code == 200


def test_privacy_gateway_redacts_confidential_email(client):
    signup(client)
    memory_response = client.post(
        "/api/memories",
        json={
            "title": "Contact information",
            "content": "Contact alex@example.com about the account review.",
            "status": "Verified",
            "sensitivity": "INTERNAL",
        },
    )
    assert memory_response.status_code == 200
    record = memory_response.json()["memory"]
    preview = client.post(
        "/api/privacy/preview",
        json={"question": "Contact alex@example.com", "memory_ids": [record["id"]]},
    )
    assert preview.status_code == 200
    result = preview.json()
    assert result["decision"] == "redacted"
    assert "email" in result["redacted_categories"]
    assert "alex@example.com" not in result["preview"][0]["excerpt"]


def test_privacy_gateway_blocks_top_secret(client, database):
    signup(client)
    response = client.post(
        "/api/memories",
        json={
            "title": "Confidential account owner",
            "content": "Contact alex@example.com; password=hunter2; key sk-12345678901234567890",
            "status": "Verified",
            "sensitivity": "CONFIDENTIAL",
        },
    )
    assert response.status_code == 200
    record = response.json()["memory"]
    preview = client.post(
        "/api/privacy/preview",
        json={"question": "Contact alex@example.com", "memory_ids": [record["id"]]},
    )
    assert preview.status_code == 200
    result = preview.json()
    assert result["decision"] == "blocked"
    assert result["reason"]

    top_secret = client.post(
        "/api/memories",
        json={
            "title": "Top secret incident",
            "content": "Never transmit this record externally.",
            "status": "Verified",
            "sensitivity": "TOP_SECRET",
        },
    ).json()["memory"]
    blocked = client.post(
        "/api/privacy/preview",
        json={"question": "incident", "memory_ids": [top_secret["id"]]},
    )
    assert blocked.status_code == 200
    assert blocked.json()["decision"] == "blocked"
    chat = client.post("/api/agent/chat", json={"question": "top secret incident"})
    assert chat.status_code == 403
    assert database.audit_logs.find_one({"action": "privacy.blocked"})


def test_memory_features_audit_security_dashboard_and_csv(client):
    signup(client)
    response = client.get("/api/health")
    assert response.json() == {"status": "ok", "database": "mongodb"}
    result = client.get("/api/memories", params={"q": "incident-report-payment-014.md"})
    assert [item["id"] for item in result.json()["memories"]] == ["demo-1"]
    assert client.get("/api/handover", params={"project": "Payment Service"}).status_code == 200
    assert client.post("/api/agent/chat", json={"question": "payment timeout incident"}).status_code == 200
    audit = client.get("/api/audit")
    assert audit.status_code == 200
    assert "memory.search" in {event["action"] for event in audit.json()["events"]}
    exported = client.get("/api/audit/export")
    assert exported.status_code == 200
    assert "text/csv" in exported.headers["content-type"]
    overview = client.get("/api/security/overview")
    assert overview.status_code == 200
    assert overview.json()["configuration"]["external_ai_provider"] == "not configured"
    assert overview.json()["configuration"]["managed_kms"] == "Local development key"
    assert overview.json()["configuration"]["field_level_encryption"] == "Local development key"
    assert client.get("/api/security/audit-integrity").json()["intact"] is True
