"""Security infrastructure for AuthZLab."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from functools import lru_cache
from uuid import UUID

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from authzlab.core.config import get_settings


class TokenManager:
    """JWT token management."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._private_key: str | None = None
        self._public_key: str | None = None

    def load_keys(self, private_key: str, public_key: str) -> None:
        """Load RSA keys for JWT signing/verification."""
        self._private_key = private_key
        self._public_key = public_key

    def ensure_keys(self) -> None:
        """Load persistent keys from settings or generate an ephemeral dev pair (H-2).

        Production requires JWT_PRIVATE_KEY/JWT_PUBLIC_KEY; development and
        testing fall back to a per-process keypair with a clear limitation:
        tokens do not survive restarts and are not valid across workers.
        """
        if self._private_key and self._public_key:
            return
        private = (self.settings.jwt_private_key or "").replace("\\n", "\n") or None
        public = (self.settings.jwt_public_key or "").replace("\\n", "\n") or None
        if private and public:
            self.load_keys(private, public)
            return
        if self.settings.environment == "production":
            raise RuntimeError(
                "JWT keys not configured: set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY in production"
            )
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        self.load_keys(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        )

    def create_access_token(
        self,
        user_id: UUID,
        tenant_id: UUID,
        email: str,
        role: str,
    ) -> str:
        """Create a JWT access token."""
        if not self._private_key:
            raise RuntimeError("Private key not loaded")

        now = datetime.now(UTC)
        expire = now + timedelta(minutes=self.settings.access_token_expire_minutes)

        payload = {
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "email": email,
            "role": role,
        }

        return jwt.encode(
            payload,
            self._private_key,
            algorithm=self.settings.algorithm,
            headers={"kid": self.settings.jwt_kid},
        )

    def create_refresh_token(self, user_id: UUID) -> str:
        """Create a JWT refresh token."""
        if not self._private_key:
            raise RuntimeError("Private key not loaded")

        now = datetime.now(UTC)
        expire = now + timedelta(days=self.settings.refresh_token_expire_days)

        payload = {
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "sub": str(user_id),
            "type": "refresh",
        }

        return jwt.encode(
            payload,
            self._private_key,
            algorithm=self.settings.algorithm,
            headers={"kid": self.settings.jwt_kid},
        )

    def verify_token(self, token: str) -> dict:
        """Verify and decode a JWT token."""
        if not self._public_key:
            raise RuntimeError("Public key not loaded")

        # L-B: the kid header is written on encode, so enforce it on decode;
        # otherwise a future rotation could accept tokens for unknown keys.
        try:
            header_kid = jwt.get_unverified_header(token).get("kid")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}") from e
        if header_kid != self.settings.jwt_kid:
            raise ValueError("Invalid token: unexpected kid")

        try:
            return jwt.decode(
                token,
                self._public_key,
                algorithms=[self.settings.algorithm],
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                options={"require": ["iss", "aud", "exp", "iat", "sub"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise ValueError("Token expired") from e
        except jwt.InvalidIssuerError as e:
            raise ValueError("Invalid issuer") from e
        except jwt.InvalidAudienceError as e:
            raise ValueError("Invalid audience") from e
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}") from e


class PasswordManager:
    """Password hashing using Argon2id."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._hasher = PasswordHasher(
            time_cost=self.settings.argon2_time_cost,
            memory_cost=self.settings.argon2_memory_cost,
            parallelism=self.settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
        )

    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2id."""
        return self._hasher.hash(password)

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        try:
            self._hasher.verify(password_hash, password)
            return True
        except VerifyMismatchError:
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        """Check if hash needs to be updated with current parameters."""
        return self._hasher.check_needs_rehash(password_hash)


@lru_cache(maxsize=1)
def get_password_manager() -> PasswordManager:
    """Shared PasswordManager.

    PasswordHasher holds only the cost parameters (it salts per call), so one
    process-wide instance is equivalent to a fresh one per login and avoids
    rebuilding it on every authentication request.
    """
    return PasswordManager()
