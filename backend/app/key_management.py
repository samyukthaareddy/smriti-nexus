from __future__ import annotations

from abc import ABC, abstractmethod
import base64
import hashlib
import hmac
import os
import re
import secrets
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KMS_KEY_NAME_PATTERN = re.compile(
    r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+"
)


class KeyManagementProvider(ABC):
    @abstractmethod
    def encrypt_data_key(self, plaintext_key: bytes) -> bytes | dict[str, str]:
        """Wrap a data-encryption key with a managed key-encryption key."""

    @abstractmethod
    def decrypt_data_key(self, encrypted_key: bytes | dict[str, str]) -> bytes:
        """Unwrap a data-encryption key."""


class GoogleCloudKMSProvider(KeyManagementProvider):
    """Wrap envelope data keys with a symmetric Google Cloud KMS CryptoKey."""

    def __init__(self, key_name: str, client: Any | None = None):
        if not _KMS_KEY_NAME_PATTERN.fullmatch(key_name):
            raise ValueError(
                "GCP_KMS_KEY_NAME must be a full Google Cloud KMS CryptoKey resource name."
            )
        self.key_name = key_name
        self.client = client if client is not None else google_kms_client()

    def encrypt_data_key(self, plaintext_key: bytes) -> dict[str, str]:
        try:
            response = self.client.encrypt(
                request={"name": self.key_name, "plaintext": plaintext_key}
            )
        except _google_kms_errors() as exc:
            raise RuntimeError(
                "Google Cloud KMS could not encrypt the data key. Check ADC credentials, IAM permissions, and CryptoKey configuration."
            ) from exc
        return {
            "provider": "google-cloud-kms",
            "key_name": self.key_name,
            "ciphertext": base64.urlsafe_b64encode(response.ciphertext).decode("ascii"),
        }

    def decrypt_data_key(self, encrypted_key: bytes | dict[str, str]) -> bytes:
        if not isinstance(encrypted_key, dict):
            raise ValueError(
                "This envelope uses a legacy key format; configure its original development key to decrypt it."
            )
        if (
            encrypted_key.get("provider") != "google-cloud-kms"
            or encrypted_key.get("key_name") != self.key_name
        ):
            raise ValueError(
                "The envelope was wrapped by a different KMS provider or key."
            )
        try:
            response = self.client.decrypt(
                request={
                    "name": self.key_name,
                    "ciphertext": base64.urlsafe_b64decode(encrypted_key["ciphertext"]),
                }
            )
        except _google_kms_errors() as exc:
            raise RuntimeError(
                "Google Cloud KMS could not decrypt the data key. Check ADC credentials, IAM permissions, and CryptoKey configuration."
            ) from exc
        return response.plaintext


def _google_kms_errors() -> tuple[type[Exception], ...]:
    from google.api_core.exceptions import GoogleAPICallError
    from google.auth.exceptions import GoogleAuthError

    return GoogleAPICallError, GoogleAuthError


@lru_cache(maxsize=1)
def google_kms_client() -> Any:
    try:
        from google.cloud import kms_v1
    except ImportError as exc:
        raise RuntimeError(
            "Google Cloud KMS support is unavailable; install the google-cloud-kms dependency."
        ) from exc
    try:
        return kms_v1.KeyManagementServiceClient()
    except _google_kms_errors() as exc:
        raise RuntimeError(
            "Google Cloud KMS client could not initialize. Configure Application Default Credentials."
        ) from exc


class DevelopmentKeyProvider(KeyManagementProvider):
    """Local-only AES-GCM key wrapper; it must never be enabled in production."""

    def __init__(self, configured_key: str):
        if os.getenv("ENVIRONMENT", "development").lower() == "production":
            raise RuntimeError("The development key provider cannot be used in production.")
        if len(configured_key.encode("utf-8")) < 32:
            raise RuntimeError("DEV_FIELD_ENCRYPTION_KEY must contain at least 32 bytes.")
        self._key = hashlib.sha256(configured_key.encode("utf-8")).digest()

    def encrypt_data_key(self, plaintext_key: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        wrapped = AESGCM(self._key).encrypt(nonce, plaintext_key, b"smriti-dek-v1")
        return nonce + wrapped

    def decrypt_data_key(self, encrypted_key: bytes | dict[str, str]) -> bytes:
        if isinstance(encrypted_key, dict):
            if encrypted_key.get("provider") != "development":
                raise ValueError("The envelope was not wrapped by the development key.")
            encrypted_key = base64.urlsafe_b64decode(encrypted_key["ciphertext"])
        if len(encrypted_key) < 29:
            raise ValueError("Encrypted data key is malformed.")
        return AESGCM(self._key).decrypt(
            encrypted_key[:12], encrypted_key[12:], b"smriti-dek-v1"
        )


class LocalMasterKeyProvider(KeyManagementProvider):
    """Development-only AES-GCM wrapper keyed by LOCAL_MASTER_KEY."""

    def __init__(self, configured_key: str):
        if os.getenv("ENVIRONMENT", "development").lower() == "production":
            raise RuntimeError("The local master key cannot be used in production.")
        if len(configured_key.encode("utf-8")) < 32:
            raise RuntimeError("LOCAL_MASTER_KEY must contain at least 32 bytes.")
        if configured_key.lower().startswith("replace-with-"):
            raise RuntimeError("Replace the LOCAL_MASTER_KEY example placeholder.")
        self._key = hashlib.sha256(
            configured_key.encode("utf-8") + b"smriti-local-master-key-v1"
        ).digest()

    def encrypt_data_key(self, plaintext_key: bytes) -> dict[str, str]:
        nonce = secrets.token_bytes(12)
        wrapped = AESGCM(self._key).encrypt(
            nonce, plaintext_key, b"smriti-local-dek-v1"
        )
        return {
            "provider": "local",
            "ciphertext": base64.urlsafe_b64encode(nonce + wrapped).decode("ascii"),
        }

    def decrypt_data_key(self, encrypted_key: bytes | dict[str, str]) -> bytes:
        if not isinstance(encrypted_key, dict) or encrypted_key.get("provider") != "local":
            raise ValueError("The envelope was not wrapped by the local master key.")
        wrapped = base64.urlsafe_b64decode(encrypted_key["ciphertext"])
        if len(wrapped) < 29:
            raise ValueError("Encrypted data key is malformed.")
        return AESGCM(self._key).decrypt(
            wrapped[:12], wrapped[12:], b"smriti-local-dek-v1"
        )


class EnvelopeEncryptor:
    def __init__(self, key_provider: KeyManagementProvider):
        self.key_provider = key_provider

    def encrypt(self, plaintext: bytes) -> dict[str, str]:
        data_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, b"smriti-memory-v1")
        wrapped_key = self.key_provider.encrypt_data_key(data_key)
        return {
            "version": "2",
            "wrapped_key": (
                wrapped_key
                if isinstance(wrapped_key, dict)
                else {
                    "provider": "development",
                    "ciphertext": base64.urlsafe_b64encode(wrapped_key).decode("ascii"),
                }
            ),
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        }

    def decrypt(self, envelope: dict[str, str]) -> bytes:
        wrapped_key = envelope.get("wrapped_key")
        if wrapped_key is None:
            # Read envelopes created before the provider metadata was added.
            wrapped_key = base64.urlsafe_b64decode(envelope["key"])
        nonce = base64.urlsafe_b64decode(envelope["nonce"])
        ciphertext = base64.urlsafe_b64decode(envelope["ciphertext"])
        data_key = self.key_provider.decrypt_data_key(wrapped_key)
        return AESGCM(data_key).decrypt(nonce, ciphertext, b"smriti-memory-v1")


def configured_encryptor() -> EnvelopeEncryptor | None:
    provider_name = os.getenv("KMS_PROVIDER", "").lower()
    if provider_name == "local":
        configured_key = os.getenv("LOCAL_MASTER_KEY", "")
        if not configured_key:
            raise RuntimeError(
                "LOCAL_MASTER_KEY must be set when KMS_PROVIDER=local."
            )
        return EnvelopeEncryptor(LocalMasterKeyProvider(configured_key))
    if provider_name == "google-cloud-kms":
        key_name = os.getenv("GCP_KMS_KEY_NAME", "")
        if not key_name:
            raise RuntimeError(
                "GCP_KMS_KEY_NAME must be set when KMS_PROVIDER=google-cloud-kms."
            )
        return EnvelopeEncryptor(GoogleCloudKMSProvider(key_name))
    if provider_name:
        raise RuntimeError(
            "Unsupported KMS_PROVIDER. Use local for development or google-cloud-kms for production."
        )
    # Keep the legacy development key available only for decrypting existing envelopes.
    configured_key = os.getenv("DEV_FIELD_ENCRYPTION_KEY")
    if not configured_key:
        return None
    return EnvelopeEncryptor(DevelopmentKeyProvider(configured_key))


def local_master_key_configured() -> bool:
    configured_key = os.getenv("LOCAL_MASTER_KEY", "")
    return (
        os.getenv("KMS_PROVIDER", "").lower() == "local"
        and len(configured_key.encode("utf-8")) >= 32
        and not configured_key.lower().startswith("replace-with-")
        and os.getenv("ENVIRONMENT", "development").lower() != "production"
    )


def protect_content(content: str, sensitivity: str) -> dict[str, object]:
    document: dict[str, object] = {"content": content}
    if sensitivity not in {"CONFIDENTIAL", "TOP_SECRET"}:
        return document
    encryptor = configured_encryptor()
    if encryptor is None:
        raise RuntimeError(
            "Confidential memory storage requires a key provider. Configure LOCAL_MASTER_KEY for local development or Google Cloud KMS for production."
        )
    document["content"] = ""
    document["content_envelope"] = encryptor.encrypt(content.encode("utf-8"))
    return document


def reveal_content(document: dict[str, object]) -> str:
    envelope = document.get("content_envelope")
    if not isinstance(envelope, dict):
        return str(document.get("content", ""))
    encryptor = configured_encryptor()
    if encryptor is None:
        raise RuntimeError("The encryption key required to read this memory is unavailable.")
    return encryptor.decrypt(envelope).decode("utf-8")


def content_search_tokens(content: str) -> list[str]:
    configured_key = (
        os.getenv("SEARCH_INDEX_KEY")
        if os.getenv("KMS_PROVIDER", "").lower() == "google-cloud-kms"
        else os.getenv("LOCAL_MASTER_KEY")
        if os.getenv("KMS_PROVIDER", "").lower() == "local"
        else os.getenv("DEV_FIELD_ENCRYPTION_KEY")
    )
    if not configured_key:
        return []
    index_key = hashlib.sha256(
        configured_key.encode("utf-8") + b"smriti-search-index-v1"
    ).digest()
    words = set(re.findall(r"[a-zA-Z0-9]{3,}", content.lower()))
    return sorted(
        hmac.new(index_key, word.encode("utf-8"), hashlib.sha256).hexdigest()
        for word in words
    )


def query_search_tokens(query: str) -> list[str]:
    return content_search_tokens(query)


def validate_production_key_provider() -> None:
    if os.getenv("KMS_PROVIDER", "").lower() != "google-cloud-kms":
        raise RuntimeError(
            "Production requires KMS_PROVIDER=google-cloud-kms; local master keys are development-only."
        )
    key_name = os.getenv("GCP_KMS_KEY_NAME", "")
    if not key_name:
        raise RuntimeError(
            "GCP_KMS_KEY_NAME must be configured for the production key provider."
        )
    if not _KMS_KEY_NAME_PATTERN.fullmatch(key_name):
        raise RuntimeError(
            "GCP_KMS_KEY_NAME must be a full Google Cloud KMS CryptoKey resource name."
        )
    if len(os.getenv("SEARCH_INDEX_KEY", "").encode("utf-8")) < 32:
        raise RuntimeError(
            "SEARCH_INDEX_KEY must contain at least 32 bytes when production field encryption is enabled."
        )
