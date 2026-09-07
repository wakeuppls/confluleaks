from dataclasses import dataclass, field
from enum import Enum

import requests
from requests.auth import HTTPBasicAuth


class AuthMethod(str, Enum):
    BEARER = "bearer"
    BASIC = "basic"


class AuthConfigurationError(ValueError):
    """Authentication settings are missing or internally inconsistent."""


@dataclass(frozen=True)
class ConfluenceAuth:
    method: AuthMethod
    secret: str = field(repr=False)
    username: str = ""

    @classmethod
    def bearer(cls, token: str) -> "ConfluenceAuth":
        return cls(AuthMethod.BEARER, _validated_secret(token))

    @classmethod
    def basic(cls, username: str, password_or_token: str) -> "ConfluenceAuth":
        if not isinstance(username, str) or not username.strip():
            raise AuthConfigurationError(
                "a non-empty username is required for Basic authentication"
            )
        normalized_username = username.strip()
        if ":" in normalized_username:
            raise AuthConfigurationError(
                "Basic authentication username must not contain ':'"
            )
        if "\r" in normalized_username or "\n" in normalized_username:
            raise AuthConfigurationError(
                "Basic authentication username must not contain newlines"
            )
        return cls(
            AuthMethod.BASIC,
            _validated_secret(password_or_token),
            username=normalized_username,
        )

    def apply(self, session: requests.Session) -> None:
        session.headers.pop("Authorization", None)
        session.auth = None
        if self.method is AuthMethod.BEARER:
            session.headers["Authorization"] = f"Bearer {self.secret}"
            return
        if self.method is AuthMethod.BASIC:
            session.auth = HTTPBasicAuth(self.username, self.secret)
            return
        raise AuthConfigurationError(
            f"unsupported authentication method: {self.method}"
        )


def _validated_secret(secret: str) -> str:
    if not isinstance(secret, str) or not secret.strip():
        raise AuthConfigurationError("a non-empty authentication secret is required")
    if "\r" in secret or "\n" in secret:
        raise AuthConfigurationError("authentication secret must not contain newlines")
    return secret
