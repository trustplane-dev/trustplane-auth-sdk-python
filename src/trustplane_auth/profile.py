from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class SigningProfile:
    state: str
    reason: str
    key_origin: str
    request_base_url: str
    key_id: str
    subject: str
    trust_domain: str
    issuer: str
    route_id: str
    canonical_route_id: str
    route_match_type: str
    route_path: str
    method: str
    audience: str
    control: Mapping[str, Any]

    @classmethod
    def from_control(cls, raw: Mapping[str, Any]) -> SigningProfile:
        profile = cls(
            state=_text(raw.get("state")),
            reason=_text(raw.get("reason")),
            key_origin=_text(raw.get("key_origin")),
            request_base_url=_text(raw.get("request_base_url")) or _text(raw.get("auth_site_url")),
            key_id=_text(raw.get("kid")),
            subject=_text(raw.get("subject")),
            trust_domain=_text(raw.get("trust_domain")),
            issuer=_text(raw.get("issuer")),
            route_id=_text(raw.get("route_id")),
            canonical_route_id=_text(raw.get("canonical_route_id")),
            route_match_type=_text(raw.get("route_match_type")),
            route_path=_text(raw.get("route_path")),
            method=_text(raw.get("method")).upper(),
            audience=_text(raw.get("audience")),
            control=dict(raw),
        )
        profile.validate_active()
        return profile

    def validate_active(self) -> None:
        if self.state != "active":
            suffix = f": {self.reason}" if self.reason else ""
            raise ValueError(f"signing_profile_unavailable{suffix}")
        required = {
            "request_base_url": self.request_base_url,
            "kid": self.key_id,
            "subject": self.subject,
            "trust_domain": self.trust_domain,
            "issuer": self.issuer,
            "route_id": self.route_id,
            "route_path": self.route_path,
            "method": self.method,
            "audience": self.audience,
        }
        for name, value in required.items():
            if value == "":
                raise ValueError(f"signing_profile_missing_{name}")
        if self.canonical_route_id and self.canonical_route_id != self.route_id:
            raise ValueError("signing_profile_route_id_mismatch")
        if self.route_match_type not in {"Exact", "PathPrefix"}:
            raise ValueError("signing_profile_invalid_route_match_type")
        base = urlparse(self.request_base_url)
        if (
            base.scheme not in {"http", "https"}
            or not base.netloc
            or base.username is not None
            or base.password is not None
            or bool(base.query)
            or bool(base.fragment)
        ):
            raise ValueError("signing_profile_invalid_request_base_url")

    def matches(self, method: str, path: str) -> bool:
        if method.strip().upper() != self.method:
            return False
        template = self.route_path.strip()
        if self.route_match_type == "PathPrefix":
            if template == "/":
                return path.startswith("/")
            prefix = template.rstrip("/")
            return path == prefix or path.startswith(f"{prefix}/")
        if "{" not in template:
            return path == template
        expected = template.strip("/").split("/")
        actual = path.strip("/").split("/")
        if len(expected) != len(actual):
            return False
        return all(
            bool(actual_part)
            if expected_part.startswith("{") and expected_part.endswith("}")
            else expected_part == actual_part
            for expected_part, actual_part in zip(expected, actual, strict=True)
        )


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def validate_concrete_request_path(path: str, raw_path: str | None = None) -> None:
    raw = path if raw_path is None else raw_path
    if not path.startswith("/") or not raw.startswith("/"):
        raise ValueError("unsafe_request_path")
    if path != "/" and (path.endswith("/") or raw.endswith("/")):
        raise ValueError("unsafe_request_path")
    if "//" in path or "//" in raw or "\\" in path or "\\" in raw or "%" in raw:
        raise ValueError("unsafe_request_path")
    for candidate in (path, raw):
        for segment in candidate.removeprefix("/").split("/"):
            if segment in {".", ".."} or "{" in segment or "}" in segment:
                raise ValueError("unsafe_request_path")
