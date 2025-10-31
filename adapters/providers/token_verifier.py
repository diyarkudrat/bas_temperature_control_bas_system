from __future__ import annotations

from typing import Any, Dict

from jose import jwt  # type: ignore[import]
from jose.exceptions import JWTError  # type: ignore[import]


class TokenVerifier:
    """Strict RS256 verifier enforcing audience/issuer and standard claims."""

    def verify(self, *, token: str, key: Any, audience: str, issuer: str, clock_skew_s: int) -> Dict[str, Any]:
        """Verify a token and return the claims."""

        try:
            claims = jwt.decode(
                token,
                key.to_pem().decode("utf-8"),
                algorithms=["RS256"],
                audience=audience,
                issuer=issuer,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_iat": True,
                    "verify_exp": True,
                },
                leeway=int(clock_skew_s),
            )
        except JWTError as exc:
            raise ValueError(f"invalid token: {exc}") from exc

        return dict[str, Any](claims)