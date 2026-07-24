"""Proof-of-possession workload signing-profile resolution.

This module implements the public Control workload-profile resolution v1
contract.  It deliberately has no Control credential input: possession of the
locally held enrolled Ed25519 key is the only authorization proof.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse, urlunparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .enrollment import HTTPResponse, _default_transport, _header, _retry_after
from .keys import _b64url
from .profile import SigningProfile, validate_concrete_request_path

WORKLOAD_PROFILE_CHALLENGE_PATH = "/v1/public/workload-profiles/challenges"
WORKLOAD_PROFILE_RESOLVE_PATH = "/v1/public/workload-profiles/resolve"
WORKLOAD_PROFILE_TRANSCRIPT_VERSION = "trustplane-workload-profile-resolution-pop-v1"
WORKLOAD_PROFILE_POP_DOMAIN = "trustplane-workload-profile-resolution-pop-v1"
MAX_WORKLOAD_PROFILE_RESPONSE_BYTES = 1 << 20
MAX_WORKLOAD_PROFILES = 128
MAX_WORKLOAD_PROFILE_RETRY_AFTER_SECONDS = 300


@dataclass(frozen=True)
class WorkloadProfileChallenge:
    transcript_version: str
    challenge_id: str
    nonce: str
    issued_at_unix: int
    expires_at_unix: int


@dataclass(frozen=True)
class WorkloadProfileOptions:
    control_url: str
    enrollment_policy_ref: str
    key_id: str
    private_key: Ed25519PrivateKey
    timeout: float = 30.0


@dataclass(frozen=True)
class WorkloadSigningProfile:
    """One public signing profile returned for the enrolled workload key."""

    profile_id: str
    profile_version: str
    auth_base_url: str
    key_id: str
    subject: str
    issuer: str
    trust_domain: str
    audience: str
    canonical_route_id: str
    method: str
    route_match_type: str
    route_path: str
    acknowledged_target_configuration_version: int
    expires_at_unix: int
    refresh_at_unix: int

    def to_signing_profile(self) -> SigningProfile:
        """Adapt this public resolver profile for the existing ProtectedClient."""
        return SigningProfile.from_control(
            {
                "state": "active",
                "key_origin": "trust_anchor_derived",
                "request_base_url": self.auth_base_url,
                "kid": self.key_id,
                "subject": self.subject,
                "trust_domain": self.trust_domain,
                "issuer": self.issuer,
                "route_id": self.canonical_route_id,
                "canonical_route_id": self.canonical_route_id,
                "route_match_type": self.route_match_type,
                "route_path": self.route_path,
                "method": self.method,
                "audience": self.audience,
            }
        )

    def matches(self, method: str, concrete_path: str) -> bool:
        return self.to_signing_profile().matches(method, concrete_path)


@dataclass(frozen=True)
class WorkloadProfileResolution:
    state: str
    policy_fingerprint_sha256: str
    key_id: str
    key_expires_at_unix: int
    refresh_at_unix: int
    profiles: tuple[WorkloadSigningProfile, ...]
    retry_after_seconds: int = 0

    def select_profile(self, method: str, concrete_path: str) -> WorkloadSigningProfile:
        """Select exactly one locally matching profile or fail closed."""
        if self.state != "active":
            raise WorkloadProfileError(
                f"workload_profile_{self.state}",
                retry_after=self.retry_after_seconds,
            )
        _validate_concrete_path(concrete_path)
        matches = tuple(
            profile for profile in self.profiles if profile.matches(method, concrete_path)
        )
        if not matches:
            raise WorkloadProfileError("workload_profile_no_matching_profile")
        if len(matches) != 1:
            raise WorkloadProfileError("workload_profile_ambiguous_profile")
        return matches[0]

    def select_signing_profile(self, method: str, concrete_path: str) -> SigningProfile:
        return self.select_profile(method, concrete_path).to_signing_profile()


class WorkloadProfileTransport(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HTTPResponse: ...


class WorkloadProfileError(ValueError):
    def __init__(
        self,
        code: str,
        status_code: int = 0,
        retry_after: float = 0.0,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.retry_after = retry_after


class WorkloadProfileClient:
    """Resolve public signing profiles using an enrolled key's Ed25519 proof."""

    def __init__(
        self,
        transport: WorkloadProfileTransport | None = None,
        *,
        now_unix: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._transport = transport or _default_transport
        self._now_unix = now_unix
        self._monotonic = monotonic
        self._cache: dict[tuple[str, str, str], tuple[int, WorkloadProfileResolution]] = {}
        self._cache_lock = threading.Lock()

    def create_challenge(
        self,
        control_url: str,
        enrollment_policy_ref: str,
        key_id: str,
        *,
        timeout: float = 30.0,
    ) -> WorkloadProfileChallenge:
        """Create a fresh server-issued resolver challenge without credentials."""
        base, policy_ref, enrolled_key_id, deadline = self._validated_request(
            control_url, enrollment_policy_ref, key_id, timeout
        )
        raw, _ = self._json(
            "POST",
            base,
            WORKLOAD_PROFILE_CHALLENGE_PATH,
            {"enrollment_policy_ref": policy_ref, "key_id": enrolled_key_id},
            deadline,
        )
        challenge = _challenge(raw)
        _validate_challenge(challenge, self._now_unix())
        return challenge

    def resolve(self, options: WorkloadProfileOptions) -> WorkloadProfileResolution:
        """Create, consume, and validate a resolver challenge.

        Active results are cached only through the earliest enrolled-key,
        profile-expiry, and server refresh boundary.  Pending, unavailable, and
        inactive-key responses are never cached.
        """
        base, policy_ref, enrolled_key_id, deadline = self._validated_request(
            options.control_url,
            options.enrollment_policy_ref,
            options.key_id,
            options.timeout,
        )
        cache_key = (base, policy_ref, enrolled_key_id)
        cached = self._cached(cache_key)
        if cached is not None:
            return cached
        challenge = self._create_challenge(base, policy_ref, enrolled_key_id, deadline)
        return self._resolve_challenge(
            base,
            policy_ref,
            enrolled_key_id,
            options.private_key,
            challenge,
            deadline,
            cache_key,
        )

    def resolve_challenge(
        self,
        options: WorkloadProfileOptions,
        challenge: WorkloadProfileChallenge,
    ) -> WorkloadProfileResolution:
        """Consume a previously created challenge exactly once.

        This does not read an existing cache so the supplied challenge is never
        left unconsumed.  A successful active result may populate the cache for
        later calls to :meth:`resolve`.
        """
        base, policy_ref, enrolled_key_id, deadline = self._validated_request(
            options.control_url,
            options.enrollment_policy_ref,
            options.key_id,
            options.timeout,
        )
        _validate_challenge(challenge, self._now_unix())
        return self._resolve_challenge(
            base,
            policy_ref,
            enrolled_key_id,
            options.private_key,
            challenge,
            deadline,
            (base, policy_ref, enrolled_key_id),
        )

    def _create_challenge(
        self,
        base: str,
        policy_ref: str,
        key_id: str,
        deadline: float,
    ) -> WorkloadProfileChallenge:
        raw, _ = self._json(
            "POST",
            base,
            WORKLOAD_PROFILE_CHALLENGE_PATH,
            {"enrollment_policy_ref": policy_ref, "key_id": key_id},
            deadline,
        )
        challenge = _challenge(raw)
        _validate_challenge(challenge, self._now_unix())
        return challenge

    def _resolve_challenge(
        self,
        base: str,
        policy_ref: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
        challenge: WorkloadProfileChallenge,
        deadline: float,
        cache_key: tuple[str, str, str],
    ) -> WorkloadProfileResolution:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise WorkloadProfileError("invalid_workload_private_key")
        signature = private_key.sign(
            workload_profile_pop_transcript(
                challenge.challenge_id,
                challenge.nonce,
                challenge.issued_at_unix,
                challenge.expires_at_unix,
                policy_ref,
                key_id,
            )
        )
        raw, headers = self._json(
            "POST",
            base,
            WORKLOAD_PROFILE_RESOLVE_PATH,
            {
                "enrollment_policy_ref": policy_ref,
                "key_id": key_id,
                "challenge_id": challenge.challenge_id,
                "nonce": challenge.nonce,
                "issued_at_unix": challenge.issued_at_unix,
                "expires_at_unix": challenge.expires_at_unix,
                "pop_signature_b64url": _b64url(signature),
            },
            deadline,
        )
        resolution = _resolution(raw, headers, policy_ref, key_id, self._now_unix())
        self._store_cache(cache_key, resolution)
        return resolution

    def _validated_request(
        self,
        control_url: str,
        policy_ref: str,
        key_id: str,
        timeout: float,
    ) -> tuple[str, str, str, float]:
        base = _control_url(control_url)
        if not _exact(policy_ref) or not _exact(key_id):
            raise WorkloadProfileError("workload_profile_policy_and_key_required")
        if timeout <= 0:
            raise WorkloadProfileError("invalid_workload_profile_timeout")
        return base, policy_ref, key_id, self._monotonic() + timeout

    def _json(
        self,
        method: str,
        base: str,
        path: str,
        value: Mapping[str, object],
        deadline: float,
    ) -> tuple[dict[str, object], Mapping[str, str]]:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise WorkloadProfileError("workload_profile_timeout")
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        try:
            response = self._transport(
                method,
                _endpoint(base, path),
                {"Accept": "application/json", "Content-Type": "application/json"},
                body,
                remaining,
            )
        except TimeoutError as exc:
            raise WorkloadProfileError("workload_profile_timeout") from exc
        except OSError as exc:
            raise WorkloadProfileError("control_unavailable") from exc
        if len(response.body) > MAX_WORKLOAD_PROFILE_RESPONSE_BYTES:
            raise WorkloadProfileError("control_response_invalid")
        if not 200 <= response.status < 300:
            if response.status == 429:
                raise WorkloadProfileError(
                    "control_throttled",
                    response.status,
                    min(
                        _retry_after(_header(response.headers, "Retry-After")),
                        float(MAX_WORKLOAD_PROFILE_RETRY_AFTER_SECONDS),
                    ),
                )
            if response.status >= 500:
                raise WorkloadProfileError("control_transient_failure", response.status)
            # The public resolver intentionally does not expose remote codes:
            # unknown policy/key, invalid proof, expiry, and replay are opaque.
            raise WorkloadProfileError("workload_profile_resolution_failed", response.status)
        try:
            decoded = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkloadProfileError("control_response_invalid") from exc
        if not isinstance(decoded, dict):
            raise WorkloadProfileError("control_response_invalid")
        return decoded, response.headers

    def _cached(self, cache_key: tuple[str, str, str]) -> WorkloadProfileResolution | None:
        now = int(self._now_unix())
        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry is None:
                return None
            expires_at, resolution = entry
            if expires_at <= now:
                del self._cache[cache_key]
                return None
            return resolution

    def _store_cache(
        self,
        cache_key: tuple[str, str, str],
        resolution: WorkloadProfileResolution,
    ) -> None:
        if resolution.state != "active":
            return
        boundary = min(
            resolution.key_expires_at_unix,
            resolution.refresh_at_unix,
            *(profile.expires_at_unix for profile in resolution.profiles),
            *(profile.refresh_at_unix for profile in resolution.profiles),
        )
        if boundary <= int(self._now_unix()):
            return
        with self._cache_lock:
            self._cache[cache_key] = (boundary, resolution)


def workload_profile_pop_transcript(
    challenge_id: str,
    nonce: str,
    issued_at_unix: int,
    expires_at_unix: int,
    enrollment_policy_ref: str,
    key_id: str,
) -> bytes:
    """Return the exact v1 UTF-8 Ed25519 proof transcript."""
    if not all(_exact(value) for value in (challenge_id, nonce, enrollment_policy_ref, key_id)):
        raise WorkloadProfileError("invalid_workload_profile_transcript_field")
    if not _positive_int(issued_at_unix) or not _positive_int(expires_at_unix):
        raise WorkloadProfileError("invalid_workload_profile_transcript_time")
    return (
        f"{WORKLOAD_PROFILE_POP_DOMAIN}\n"
        "POST\n"
        f"{WORKLOAD_PROFILE_RESOLVE_PATH}\n"
        f"{challenge_id}\n"
        f"{nonce}\n"
        f"{issued_at_unix}\n"
        f"{expires_at_unix}\n"
        f"{_policy_fingerprint(enrollment_policy_ref)}\n"
        f"{key_id}\n"
    ).encode()


def _challenge(raw: Mapping[str, object]) -> WorkloadProfileChallenge:
    _exact_keys(
        raw,
        {
            "transcript_version",
            "challenge_id",
            "nonce",
            "issued_at_unix",
            "expires_at_unix",
        },
        "malformed_workload_profile_challenge",
    )
    return WorkloadProfileChallenge(
        transcript_version=_string(raw, "transcript_version"),
        challenge_id=_string(raw, "challenge_id"),
        nonce=_string(raw, "nonce"),
        issued_at_unix=_integer(raw, "issued_at_unix"),
        expires_at_unix=_integer(raw, "expires_at_unix"),
    )


def _validate_challenge(challenge: WorkloadProfileChallenge, now_unix: float) -> None:
    if challenge.transcript_version != WORKLOAD_PROFILE_TRANSCRIPT_VERSION:
        raise WorkloadProfileError("unsupported_workload_profile_transcript_version")
    if not _exact(challenge.challenge_id) or not _exact(challenge.nonce):
        raise WorkloadProfileError("malformed_workload_profile_challenge")
    if (
        not _positive_int(challenge.issued_at_unix)
        or not _positive_int(challenge.expires_at_unix)
        or challenge.expires_at_unix <= challenge.issued_at_unix
        or challenge.expires_at_unix <= int(now_unix)
    ):
        raise WorkloadProfileError("malformed_workload_profile_challenge")


def _resolution(
    raw: Mapping[str, object],
    headers: Mapping[str, str],
    policy_ref: str,
    key_id: str,
    now_unix: float,
) -> WorkloadProfileResolution:
    if "no-store" not in {
        directive.strip().lower() for directive in _header(headers, "Cache-Control").split(",")
    }:
        raise WorkloadProfileError("malformed_workload_profile_response")
    state = _string(raw, "state")
    allowed = {
        "state",
        "policy_fingerprint_sha256",
        "key_id",
        "key_expires_at_unix",
        "refresh_at_unix",
        "profiles",
    }
    if state == "pending":
        allowed.add("retry_after_seconds")
    _exact_keys(raw, allowed, "malformed_workload_profile_response")
    if state not in {"active", "pending", "inactive_key", "unavailable"}:
        raise WorkloadProfileError("malformed_workload_profile_response")
    fingerprint = _string(raw, "policy_fingerprint_sha256")
    if fingerprint != _policy_fingerprint(policy_ref) or _string(raw, "key_id") != key_id:
        raise WorkloadProfileError("workload_profile_binding_mismatch")
    key_expires_at_unix = _integer(raw, "key_expires_at_unix")
    refresh_at_unix = _integer(raw, "refresh_at_unix")
    profiles_raw = raw.get("profiles")
    if not isinstance(profiles_raw, list) or len(profiles_raw) > MAX_WORKLOAD_PROFILES:
        raise WorkloadProfileError("malformed_workload_profile_response")
    if not _positive_int(key_expires_at_unix) or not _positive_int(refresh_at_unix):
        raise WorkloadProfileError("malformed_workload_profile_response")
    retry_after_seconds = 0
    if state == "pending":
        retry_after_seconds = _integer(raw, "retry_after_seconds")
        header_retry_after = _retry_after(_header(headers, "Retry-After"))
        if (
            not _positive_int(retry_after_seconds)
            or retry_after_seconds > MAX_WORKLOAD_PROFILE_RETRY_AFTER_SECONDS
            or int(header_retry_after) != retry_after_seconds
        ):
            raise WorkloadProfileError("malformed_workload_profile_response")
    if state != "active" and profiles_raw:
        raise WorkloadProfileError("malformed_workload_profile_response")
    if state in {"active", "pending"} and (
        key_expires_at_unix <= int(now_unix) or refresh_at_unix <= int(now_unix)
    ):
        raise WorkloadProfileError("malformed_workload_profile_response")
    profiles = tuple(
        _profile(value, key_id, key_expires_at_unix, now_unix) for value in profiles_raw
    )
    if state == "active" and not profiles:
        raise WorkloadProfileError("malformed_workload_profile_response")
    return WorkloadProfileResolution(
        state=state,
        policy_fingerprint_sha256=fingerprint,
        key_id=key_id,
        key_expires_at_unix=key_expires_at_unix,
        refresh_at_unix=refresh_at_unix,
        profiles=profiles,
        retry_after_seconds=retry_after_seconds,
    )


def _profile(
    raw: object,
    expected_key_id: str,
    key_expires_at_unix: int,
    now_unix: float,
) -> WorkloadSigningProfile:
    if not isinstance(raw, Mapping):
        raise WorkloadProfileError("malformed_workload_profile_response")
    _exact_keys(
        raw,
        {
            "profile_id",
            "profile_version",
            "auth_base_url",
            "key_id",
            "subject",
            "issuer",
            "trust_domain",
            "audience",
            "canonical_route_id",
            "method",
            "route_match_type",
            "route_path",
            "acknowledged_target_configuration_version",
            "expires_at_unix",
            "refresh_at_unix",
        },
        "malformed_workload_profile_response",
    )
    profile = WorkloadSigningProfile(
        profile_id=_string(raw, "profile_id"),
        profile_version=_string(raw, "profile_version"),
        auth_base_url=_string(raw, "auth_base_url"),
        key_id=_string(raw, "key_id"),
        subject=_string(raw, "subject"),
        issuer=_string(raw, "issuer"),
        trust_domain=_string(raw, "trust_domain"),
        audience=_string(raw, "audience"),
        canonical_route_id=_string(raw, "canonical_route_id"),
        method=_string(raw, "method"),
        route_match_type=_string(raw, "route_match_type"),
        route_path=_string(raw, "route_path"),
        acknowledged_target_configuration_version=_integer(
            raw, "acknowledged_target_configuration_version"
        ),
        expires_at_unix=_integer(raw, "expires_at_unix"),
        refresh_at_unix=_integer(raw, "refresh_at_unix"),
    )
    if (
        not all(
            _exact(value)
            for value in (
                profile.profile_id,
                profile.profile_version,
                profile.auth_base_url,
                profile.key_id,
                profile.subject,
                profile.issuer,
                profile.trust_domain,
                profile.audience,
                profile.canonical_route_id,
                profile.method,
                profile.route_match_type,
                profile.route_path,
            )
        )
        or profile.key_id != expected_key_id
        or profile.profile_version != "workload-signing-profile-v1"
        or profile.method != profile.method.upper()
        or not _positive_int(profile.acknowledged_target_configuration_version)
        or not _positive_int(profile.expires_at_unix)
        or not _positive_int(profile.refresh_at_unix)
        or profile.expires_at_unix > key_expires_at_unix
        or profile.expires_at_unix <= int(now_unix)
        or profile.refresh_at_unix <= int(now_unix)
        or (profile.route_match_type == "PathPrefix" and "{" in profile.route_path)
    ):
        raise WorkloadProfileError("malformed_workload_profile_response")
    try:
        profile.to_signing_profile().validate_active()
        _validate_concrete_path(profile.route_path, allow_template=True)
    except ValueError as exc:
        raise WorkloadProfileError("malformed_workload_profile_response") from exc
    return profile


def _validate_concrete_path(path: str, *, allow_template: bool = False) -> None:
    if not _exact(path) or "?" in path or "#" in path or ";" in path:
        raise WorkloadProfileError("unsafe_request_path")
    if allow_template:
        if not path.startswith("/") or path != "/" and path.endswith("/"):
            raise WorkloadProfileError("unsafe_request_path")
        if path == "/":
            return
        # Existing SigningProfile.matches supports only whole path-segment
        # templates.  Do not accept a resolver response it cannot select safely.
        for segment in path.removeprefix("/").split("/"):
            if segment in {"", ".", ".."} or "\\" in segment or "%" in segment:
                raise WorkloadProfileError("unsafe_request_path")
            if ("{" in segment or "}" in segment) and not re.fullmatch(
                r"\{[A-Za-z][A-Za-z0-9_-]*\}", segment
            ):
                raise WorkloadProfileError("unsafe_request_path")
        return
    validate_concrete_request_path(path)


def _exact_keys(raw: Mapping[str, object], allowed: set[str], code: str) -> None:
    if set(raw) != allowed:
        raise WorkloadProfileError(code)


def _string(raw: Mapping[str, object], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str):
        raise WorkloadProfileError("malformed_workload_profile_response")
    return value


def _integer(raw: Mapping[str, object], name: str) -> int:
    value = raw.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise WorkloadProfileError("malformed_workload_profile_response")
    return value


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _policy_fingerprint(policy_ref: str) -> str:
    return f"sha256:{hashlib.sha256(policy_ref.encode('utf-8')).hexdigest()}"


def _control_url(raw: str) -> str:
    parsed = urlparse(raw.strip())
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise WorkloadProfileError("invalid_control_url")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def _endpoint(base: str, path: str) -> str:
    parsed = urlparse(base)
    return urlunparse(
        (parsed.scheme, parsed.netloc, f"{parsed.path.rstrip('/')}{path}", "", "", "")
    )


def _exact(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()
