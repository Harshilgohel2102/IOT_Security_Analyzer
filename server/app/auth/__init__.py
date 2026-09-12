"""
Authentication Module
=====================
Provides API key-based authentication middleware and utilities
for securing the IoT Security Platform endpoints.

In production deployments, this module should be extended with:
- OAuth2 / JWT token-based authentication
- Role-based access control (RBAC)
- TLS certificate validation for agent-server communication
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader

# ============================================================
# Configuration
# ============================================================
# API key for agent-server communication.
# In production, set IOT_API_KEY environment variable.
# If not set, authentication is disabled (development mode).
API_KEY_ENV = "IOT_API_KEY"
API_KEY_HEADER_NAME = "X-API-Key"

api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)


def get_configured_api_key() -> Optional[str]:
    """Retrieve the configured API key from environment."""
    return os.getenv(API_KEY_ENV)


def generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    return secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """Create a SHA-256 hash of an API key for safe storage."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_api_key(provided_key: str, stored_key: str) -> bool:
    """
    Constant-time comparison of API keys to prevent timing attacks.
    """
    return hmac.compare_digest(provided_key, stored_key)


async def validate_api_key(api_key: Optional[str] = Security(api_key_header)) -> Optional[str]:
    """
    FastAPI dependency that validates the API key from request headers.

    - If IOT_API_KEY environment variable is NOT set, authentication
      is disabled (development mode) and all requests are allowed.
    - If IOT_API_KEY IS set, requests must include a valid
      X-API-Key header.
    """
    configured_key = get_configured_api_key()

    # Development mode: no API key configured, skip auth
    if configured_key is None:
        return None

    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header.",
        )

    if not verify_api_key(api_key, configured_key):
        raise HTTPException(
            status_code=403,
            detail="Invalid API key.",
        )

    return api_key


class AuthContext:
    """
    Lightweight authentication context for tracking authenticated
    requests and agent identity.
    """

    def __init__(self, api_key: Optional[str] = None, agent_name: Optional[str] = None):
        self.api_key = api_key
        self.agent_name = agent_name
        self.authenticated_at = datetime.now(timezone.utc)
        self.is_authenticated = api_key is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_authenticated": self.is_authenticated,
            "agent_name": self.agent_name,
            "authenticated_at": self.authenticated_at.isoformat(),
        }
