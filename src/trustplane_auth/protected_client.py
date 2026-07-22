from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .passport import IssuedPassport, PassportOptions, issue_passport
from .profile import SigningProfile, validate_concrete_request_path
from .signing import sign_request
from .transcript import (
    HEADER_AUTHORIZATION,
    HEADER_BODY_SHA256,
    HEADER_NONCE,
    HEADER_PROOF,
    HEADER_TRANSCRIPT_SHA256,
    Header,
    RequestInput,
)

_RESERVED_HEADERS = {
    HEADER_AUTHORIZATION.lower(),
    HEADER_BODY_SHA256.lower(),
    HEADER_NONCE.lower(),
    HEADER_PROOF.lower(),
    HEADER_TRANSCRIPT_SHA256.lower(),
}


@dataclass(frozen=True)
class PreparedRequest:
    request: Request
    passport: IssuedPassport
    transcript_sha256: str
    body_sha256: str
    canonical_lines: tuple[str, ...]


class ProtectedClient:
    def __init__(
        self,
        profile: SigningProfile,
        private_key: Ed25519PrivateKey,
        *,
        passport_ttl: timedelta = timedelta(minutes=10),
        now: Callable[[], datetime] | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        profile.validate_active()
        self.profile = profile
        self.private_key = private_key
        self.passport_ttl = passport_ttl
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._random_bytes = random_bytes

    def prepare(
        self,
        method: str,
        path_and_query: str = "",
        body: bytes | str = b"",
        headers: Mapping[str, str] | None = None,
    ) -> PreparedRequest:
        method = method.strip().upper()
        base = urlparse(self.profile.request_base_url)
        raw_target = path_and_query or self.profile.route_path
        if raw_target.startswith("?"):
            raw_target = f"{self.profile.route_path}{raw_target}"
        reference = urlparse(raw_target)
        if reference.scheme or reference.netloc or reference.fragment:
            raise ValueError("invalid_request_path")
        wire_path = reference.path + (f";{reference.params}" if reference.params else "")
        raw_path = raw_target.split("?", 1)[0].split("#", 1)[0]
        validate_concrete_request_path(wire_path, raw_path)
        target = urlparse(
            urlunparse(
                (
                    base.scheme,
                    base.netloc,
                    wire_path,
                    "",
                    reference.query,
                    "",
                )
            )
        )
        if not self.profile.matches(method, wire_path):
            raise ValueError("request_outside_signing_profile")
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        if method in {"GET", "HEAD"} and body_bytes:
            raise ValueError("request_body_not_allowed_for_method")
        output_headers = dict(headers or {})
        if any(name.lower() in _RESERVED_HEADERS for name in output_headers):
            raise ValueError("reserved_trustplane_header")
        nonce = self._random_bytes(16).hex()
        output_headers[HEADER_NONCE] = nonce
        proof_headers = tuple(
            Header(name=name.lower(), value=value) for name, value in output_headers.items()
        )
        covered = tuple(sorted(name.lower() for name in output_headers))
        passport = issue_passport(
            PassportOptions(
                issuer=self.profile.issuer,
                subject=self.profile.subject,
                audience=self.profile.audience,
                trust_domain=self.profile.trust_domain,
                key_id=self.profile.key_id,
                private_key=self.private_key,
                ttl=self.passport_ttl,
                now=self._now(),
                random_bytes=self._random_bytes,
            )
        )
        signed = sign_request(
            request=RequestInput(
                method=method,
                scheme=target.scheme,
                authority=target.netloc,
                path=wire_path,
                raw_query=target.query,
                audience=self.profile.audience,
                route_id=self.profile.route_id,
                content_encoding=_header(output_headers, "content-encoding") or "identity",
                body=body_bytes,
                headers=proof_headers,
                header_allow_list=covered,
                nonce=nonce,
            ),
            passport_token=passport.token,
            private_key=self.private_key,
        )
        output_headers.update(signed.headers)
        request = Request(
            target.geturl(), data=body_bytes or None, headers=output_headers, method=method
        )
        return PreparedRequest(
            request=request,
            passport=passport,
            transcript_sha256=signed.transcript_sha256,
            body_sha256=signed.body_sha256,
            canonical_lines=signed.canonical_lines,
        )

    def request(
        self,
        method: str,
        path_and_query: str = "",
        body: bytes | str = b"",
        headers: Mapping[str, str] | None = None,
        *,
        timeout: float = 30.0,
    ) -> object:
        return build_opener(_NoRedirect()).open(
            self.prepare(method, path_and_query, body, headers).request,
            timeout=timeout,
        )


def _header(headers: Mapping[str, str], wanted: str) -> str:
    for name, value in headers.items():
        if name.lower() == wanted:
            return value.strip()
    return ""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None
