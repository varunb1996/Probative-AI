"""A static bearer token for write endpoints. Demo-grade: say so wherever it is deployed."""

import hmac


def token_ok(header: str | None, token: str) -> bool:
    if not token or not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header.removeprefix("Bearer "), token)
