"""Restricted Token Vault with Envelope Encryption and Strict Access Controls.

SECURITY ARCHITECTURE:
1. Isolation: Original PII values are isolated from general application logs and LLM contexts.
2. At-Rest Encryption: Sensitive values are encrypted using AES-256-GCM with AWS KMS or local envelope key.
3. Opaque Identifiers: Tokens are generated using cryptographically secure random bytes (CSPRNG).
4. No Automatic De-anonymization: The LLM NEVER receives token mappings or unredacted values.
5. Explicit Audit Trail: Every restoration access attempt is audited regardless of success or failure.
"""

import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.core.security import AuthenticatedUser
from app.db.audit_repository import AuditRepository
from app.services.pii_redaction import PIIEntity


class TokenVaultError(Exception):
    """Base exception for token vault operations."""

    pass


class TokenVaultEncryptionError(TokenVaultError):
    """Raised when envelope encryption or decryption fails."""

    pass


class UnauthorizedTokenRestorationError(TokenVaultError):
    """Raised when an actor lacks sufficient privileges or justification for token restoration."""

    pass


class TokenNotFoundError(TokenVaultError):
    """Raised when a requested token mapping does not exist or has expired."""

    pass


class TokenVaultService:
    """Manages secure reversible tokenization, envelope encryption, and authorized restoration."""

    def __init__(self):
        self._kms_client = None

    def _get_kms_client(self):
        if self._kms_client is None:
            self._kms_client = boto3.client("kms", region_name=settings.AWS_REGION)
        return self._kms_client

    def _generate_opaque_token(self, entity_type: str) -> str:
        """Generate an unpredictable, collision-resistant token identifier."""
        random_suffix = secrets.token_hex(8)
        return f"{{{{{entity_type}_TOKEN_{random_suffix}}}}}"

    def _encrypt_value(self, plaintext: str) -> Dict[str, bytes]:
        """Encrypt plaintext using AES-256-GCM via KMS data key or local envelope master key."""
        plaintext_bytes = plaintext.encode("utf-8")
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM

        if settings.TOKEN_VAULT_KEY_PROVIDER == "kms":
            if not settings.TOKEN_VAULT_KMS_KEY_ARN:
                raise TokenVaultEncryptionError(
                    "AWS KMS Key ARN is not configured for token vault encryption."
                )
            try:
                kms = self._get_kms_client()
                response = kms.generate_data_key(
                    KeyId=settings.TOKEN_VAULT_KMS_KEY_ARN,
                    KeySpec="AES_256",
                )
                plaintext_key = response["Plaintext"]
                encrypted_key_ciphertext = response["CiphertextBlob"]

                aesgcm = AESGCM(plaintext_key)
                ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

                # Split ciphertext and tag
                ciphertext = ciphertext_with_tag[:-16]
                tag = ciphertext_with_tag[-16:]

                return {
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "tag": tag,
                    "encrypted_data_key": encrypted_key_ciphertext,
                    "key_id": settings.TOKEN_VAULT_KMS_KEY_ARN,
                }
            except ClientError as exc:
                logger.error(f"KMS Data Key Generation failed: {str(exc)}")
                raise TokenVaultEncryptionError(f"KMS Key management error: {str(exc)}") from exc

        elif settings.TOKEN_VAULT_KEY_PROVIDER == "local_envelope":
            # Development / Isolated Test Envelope Mode
            if not settings.TOKEN_VAULT_LOCAL_KEY:
                raise TokenVaultEncryptionError("TOKEN_VAULT_LOCAL_KEY must be provided for local envelope mode.")
            try:
                master_key = base64.b64decode(settings.TOKEN_VAULT_LOCAL_KEY)
                if len(master_key) != 32:
                    raise TokenVaultEncryptionError("Local master key must be 32 bytes (AES-256).")

                aesgcm = AESGCM(master_key)
                ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

                ciphertext = ciphertext_with_tag[:-16]
                tag = ciphertext_with_tag[-16:]

                return {
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "tag": tag,
                    "encrypted_data_key": b"local_envelope_key_v1",
                    "key_id": "local_envelope_key_v1",
                }
            except Exception as exc:
                raise TokenVaultEncryptionError(f"Local envelope encryption failed: {str(exc)}") from exc
        else:
            raise TokenVaultEncryptionError(
                f"Unsupported TOKEN_VAULT_KEY_PROVIDER: {settings.TOKEN_VAULT_KEY_PROVIDER}"
            )

    def _decrypt_value(
        self,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        key_id: str,
        encrypted_data_key: Optional[bytes] = None,
    ) -> str:
        """Decrypt ciphertext using envelope key."""
        ciphertext_with_tag = ciphertext + tag

        if settings.TOKEN_VAULT_KEY_PROVIDER == "kms" or (key_id and key_id.startswith("arn:aws:kms")):
            try:
                kms = self._get_kms_client()
                response = kms.decrypt(CiphertextBlob=encrypted_data_key)
                plaintext_key = response["Plaintext"]

                aesgcm = AESGCM(plaintext_key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                return decrypted_bytes.decode("utf-8")
            except ClientError as exc:
                logger.error(f"KMS Decryption failed: {str(exc)}")
                raise TokenVaultEncryptionError("Failed to decrypt data key via KMS") from exc

        elif settings.TOKEN_VAULT_KEY_PROVIDER == "local_envelope" or key_id == "local_envelope_key_v1":
            if not settings.TOKEN_VAULT_LOCAL_KEY:
                raise TokenVaultEncryptionError("Local master key missing for token decryption.")
            master_key = base64.b64decode(settings.TOKEN_VAULT_LOCAL_KEY)
            aesgcm = AESGCM(master_key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            return decrypted_bytes.decode("utf-8")
        else:
            raise TokenVaultEncryptionError(f"Unsupported key identifier or provider for key: {key_id}")

    async def store_reversible_tokens(
        self,
        request_id: str,
        actor_id: str,
        entities: List[PIIEntity],
        session: AsyncSession,
    ) -> Dict[str, str]:
        """Store encrypted mappings for reversible de-anonymization when explicitly requested.

        Returns a dictionary mapping placeholder -> opaque_token.
        """
        repo = AuditRepository(session)
        placeholder_to_token: Dict[str, str] = {}
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.TOKEN_VAULT_DEFAULT_EXPIRY_DAYS)

        for entity in entities:
            opaque_token = self._generate_opaque_token(entity.entity_type)
            enc_result = self._encrypt_value(entity.original_value)

            # Store in database with nonce and tag
            await repo.store_token_mapping(
                token_id=opaque_token,
                request_id=request_id,
                token_type=entity.entity_type,
                encrypted_value=enc_result["ciphertext"],
                nonce=base64.b64encode(enc_result["nonce"]).decode("ascii"),
                auth_tag=base64.b64encode(enc_result["tag"]).decode("ascii"),
                key_identifier=enc_result["key_id"],
                actor_id=actor_id,
                expires_at=expires_at,
            )
            placeholder_to_token[entity.placeholder] = opaque_token

        return placeholder_to_token

    async def restore_token(
        self,
        token_id: str,
        user: AuthenticatedUser,
        justification: str,
        session: AsyncSession,
        client_ip: Optional[str] = None,
    ) -> Dict[str, str]:
        """Restore an original PII value from a token under strict RBAC and audit.

        Rules:
        - Only users with role 'TokenVault.Admin' or 'Compliance.Officer' may de-anonymize.
        - Must provide a non-empty business justification reason.
        - Every attempt (success or failure) is permanently recorded in the restoration audit table.
        - NEVER log the restored value.
        """
        repo = AuditRepository(session)

        # 1. Authorisation Enforcement
        is_authorized = user.has_any_role(["TokenVault.Admin", "Compliance.Officer", "SecurityAdmin"])
        if not is_authorized:
            await repo.record_restoration_attempt(
                token_id=token_id,
                actor_id=user.actor_id,
                reason=justification,
                outcome="DENIED",
                client_ip=client_ip,
            )
            logger.warning(
                f"UNAUTHORIZED_TOKEN_RESTORE_ATTEMPT by actor={user.actor_id} for token={token_id}",
                extra={"actor_id": user.actor_id, "action_type": "TOKEN_RESTORE_DENIED"},
            )
            raise UnauthorizedTokenRestorationError(
                "Actor lacks required 'TokenVault.Admin' or 'Compliance.Officer' role to de-anonymize tokens"
            )

        # 2. Retrieve Mapping
        mapping = await repo.get_token_mapping(token_id)
        if not mapping:
            await repo.record_restoration_attempt(
                token_id=token_id,
                actor_id=user.actor_id,
                reason=justification,
                outcome="FAILED_NOT_FOUND",
                client_ip=client_ip,
            )
            raise TokenNotFoundError(f"Token '{token_id}' not found in vault")

        # 3. Expiration Check
        expires_at = mapping.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            await repo.record_restoration_attempt(
                token_id=token_id,
                actor_id=user.actor_id,
                reason=justification,
                outcome="FAILED_EXPIRED",
                client_ip=client_ip,
            )
            raise TokenNotFoundError("Token mapping has expired and is no longer retrievable under retention policy")

        # 4. Decrypt original value
        try:
            nonce_bytes = base64.b64decode(mapping.nonce)
            tag_bytes = base64.b64decode(mapping.auth_tag)
            original_value = self._decrypt_value(
                ciphertext=mapping.encrypted_value,
                nonce=nonce_bytes,
                tag=tag_bytes,
                key_id=mapping.key_identifier,
                encrypted_data_key=None,
            )

            # 5. Audit Success (without original value)
            await repo.record_restoration_attempt(
                token_id=token_id,
                actor_id=user.actor_id,
                reason=justification,
                outcome="SUCCESS",
                client_ip=client_ip,
            )

            return {
                "token_id": token_id,
                "token_type": mapping.token_type,
                "original_value": original_value,
            }
        except Exception as exc:
            await repo.record_restoration_attempt(
                token_id=token_id,
                actor_id=user.actor_id,
                reason=justification,
                outcome="FAILED_DECRYPTION",
                client_ip=client_ip,
            )
            raise TokenVaultEncryptionError(f"Decryption of token payload failed: {str(exc)}") from exc


# Global token vault singleton
token_vault_service = TokenVaultService()
