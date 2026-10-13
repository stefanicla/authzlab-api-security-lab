"""JWT negative tests (H-3): token validation must reject forgeries and misissued tokens."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from authzlab.core.config import get_settings
from authzlab.infrastructure.security import TokenManager


def make_manager() -> TokenManager:
    mgr = TokenManager()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    mgr.load_keys(
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
    return mgr


def _encode_with_kid(payload: dict, key: str, algorithm: str) -> str:
    """Forge a token carrying the correct kid so kid-check passes and the
    specific negative condition under test is what fails."""
    return jwt.encode(
        payload, key=key, algorithm=algorithm, headers={"kid": get_settings().jwt_kid}
    )


def test_valid_token_verifies():
    mgr = make_manager()
    token = mgr.create_access_token(uuid4(), uuid4(), "a@test.com", "member")
    payload = mgr.verify_token(token)
    assert payload["email"] == "a@test.com"


def test_expired_token_rejected():
    mgr = make_manager()
    settings = get_settings()
    now = datetime.now(UTC) - timedelta(hours=2)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=1)).timestamp()),
        "sub": str(uuid4()),
        "tenant_id": str(uuid4()),
        "email": "a@test.com",
        "role": "member",
    }
    token = _encode_with_kid(payload, mgr._private_key, "RS256")
    with pytest.raises(ValueError, match="expired"):
        mgr.verify_token(token)


def test_tampered_signature_rejected():
    mgr = make_manager()
    token = mgr.create_access_token(uuid4(), uuid4(), "a@test.com", "member")
    # Flip the last character of the signature segment
    head, body, sig = token.split(".")
    tampered_sig = ("A" if sig[-1] != "A" else "B").join([sig[:-1], ""])
    with pytest.raises(ValueError, match="Invalid token"):
        mgr.verify_token(f"{head}.{body}.{tampered_sig}")


def test_wrong_issuer_rejected():
    mgr = make_manager()
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "iss": "evil-issuer",
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": str(uuid4()),
        "tenant_id": str(uuid4()),
        "email": "a@test.com",
        "role": "member",
    }
    token = _encode_with_kid(payload, mgr._private_key, "RS256")
    with pytest.raises(ValueError, match="issuer"):
        mgr.verify_token(token)


def test_wrong_audience_rejected():
    mgr = make_manager()
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": "evil-audience",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": str(uuid4()),
        "tenant_id": str(uuid4()),
        "email": "a@test.com",
        "role": "member",
    }
    token = _encode_with_kid(payload, mgr._private_key, "RS256")
    with pytest.raises(ValueError, match="audience"):
        mgr.verify_token(token)


def test_alg_none_rejected():
    mgr = make_manager()
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": str(uuid4()),
    }
    token = _encode_with_kid(payload, key="", algorithm="none")
    with pytest.raises(ValueError, match="Invalid token"):
        mgr.verify_token(token)


def test_rs_to_hs_confusion_rejected():
    """RS256->HS256 key confusion must fail against the RS256 allow-list."""
    mgr = make_manager()
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": str(uuid4()),
    }
    # Sign with HS256 (symmetric) while the verifier only allows RS256
    token = _encode_with_kid(payload, key="attacker-hmac-secret", algorithm="HS256")
    with pytest.raises(ValueError, match="Invalid token"):
        mgr.verify_token(token)


def test_wrong_kid_rejected():
    mgr = make_manager()
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": str(uuid4()),
    }
    token = jwt.encode(
        payload, mgr._private_key, algorithm="RS256", headers={"kid": "attacker-kid"}
    )
    with pytest.raises(ValueError, match="kid"):
        mgr.verify_token(token)


def test_missing_required_claim_rejected():
    mgr = make_manager()
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        # missing "sub"
    }
    token = _encode_with_kid(payload, mgr._private_key, "RS256")
    with pytest.raises(ValueError, match="Invalid token"):
        mgr.verify_token(token)


def test_production_requires_persistent_keys():
    from authzlab.core.config import Settings

    mgr = TokenManager()
    mgr.settings = Settings(environment="production", jwt_private_key=None, jwt_public_key=None)
    with pytest.raises(RuntimeError, match="JWT keys not configured"):
        mgr.ensure_keys()
