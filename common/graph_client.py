"""Microsoft Graph client.

Uses `msal.ConfidentialClientApplication` to acquire tokens with the
OAuth 2.0 Client Credentials Grant (CCG), then POSTs the raw MIME
message to the Graph `sendMail` endpoint.

MSAL's in-memory token cache is reused across calls so we do not
mint a new token for every mail.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
import msal

from .constants import (
    GRAPH_AUTHORITY_TEMPLATE,
    GRAPH_HTTP_TIMEOUT_SECONDS,
    GRAPH_SCOPE,
    GRAPH_SEND_MAIL_URL,
)
from .crypto import decrypt_str

if TYPE_CHECKING:  # avoid an import cycle at runtime (models imports nothing here)
    from .models import TenantConfig

_log = logging.getLogger("relay.graph")


def credential_fingerprint(cfg: "TenantConfig") -> str:
    """A cheap change-detector for the tenant's *active* credential.

    Used to decide whether a cached GraphClient is still valid. It never
    decrypts anything: for the secret path it hashes the ciphertext, which
    changes precisely when the secret is re-encrypted (i.e. rotated); for
    the certificate path it uses the thumbprint. Including tenant/client/
    method means any of those changing also invalidates the cache.
    """
    method = cfg.auth_method or "secret"
    parts = [method, cfg.tenant_id or "", cfg.client_id or ""]
    if method == "certificate":
        parts.append(cfg.cert_thumbprint or "")
    else:
        parts.append(cfg.client_secret_enc or "")
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


class GraphError(RuntimeError):
    """Raised for token or Graph API failures.

    Attributes:
        status_code: HTTP status from a Graph response, or None for
            token-acquisition and transport-level errors.
        retry_after: Server-advised delay in seconds parsed from the
            ``Retry-After`` header, when present.
        transient: True when the failure is worth retrying without
            counting against the attempt budget (throttling, transient
            server or network errors); False for permanent failures
            (auth, permission, addressing) that will not succeed on
            retry.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: float | None = None,
        transient: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after
        self.transient = transient


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a ``Retry-After`` header (delta-seconds) into float seconds.

    Microsoft Graph emits ``Retry-After`` as an integer number of
    seconds on 429/503. The HTTP-date form is not used there and is
    intentionally ignored (returns None).
    """
    if not value:
        return None
    try:
        secs = float(value.strip())
    except ValueError:
        return None
    return secs if secs >= 0 else None


@dataclass(slots=True)
class TokenInfo:
    access_token: str
    expires_at: _dt.datetime


class GraphClient:
    """Thin, cacheable Graph client for a single tenant configuration.

    Authenticates with either a client secret or a certificate, depending
    on how it is constructed (see `from_tenant_config`). A new instance
    should be built whenever the active credential changes; callers can
    compare `.fingerprint` against `credential_fingerprint(cfg)` to decide
    whether a cached client is still valid before reusing it.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        *,
        client_secret: str | None = None,
        certificate: dict[str, Any] | None = None,
        fingerprint: str = "",
    ) -> None:
        if not tenant_id or not client_id:
            raise GraphError(
                "Tenant configuration is incomplete. Configure Entra ID "
                "settings in the UI before sending mail."
            )
        if not client_secret and not certificate:
            raise GraphError(
                "No credential provided. Configure a client secret or a "
                "certificate in the UI before sending mail."
            )
        self._tenant_id = tenant_id
        self._client_id = client_id
        # `fingerprint` lets a caller cheaply check whether a cached client
        # still matches the current tenant config (see credential_fingerprint).
        self.fingerprint = fingerprint
        authority = GRAPH_AUTHORITY_TEMPLATE.format(tenant_id=tenant_id)
        # MSAL accepts either a plain string (secret) or a dict with
        # {"private_key", "thumbprint", "public_certificate"} for a cert.
        credential: str | dict[str, Any] = (
            certificate if certificate is not None else client_secret  # type: ignore[assignment]
        )
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=credential,
            authority=authority,
        )

    @classmethod
    def from_tenant_config(cls, cfg: "TenantConfig") -> "GraphClient":
        """Build a client for whichever credential the tenant row selects.

        Must be called while `cfg`'s attributes are still loaded (i.e. inside
        the DB session that fetched it), because it reads the encrypted
        credential material off the row.
        """
        method = cfg.auth_method or "secret"
        if not cfg.tenant_id or not cfg.client_id:
            raise GraphError(
                "Tenant configuration is incomplete. Configure Entra ID "
                "settings in the UI before sending mail."
            )
        fp = credential_fingerprint(cfg)
        if method == "certificate":
            if not cfg.cert_private_key_enc or not cfg.cert_thumbprint:
                raise GraphError(
                    "Certificate authentication is selected but no active "
                    "certificate is present. Generate one and activate it on "
                    "the Tenant page."
                )
            certificate = {
                "private_key": decrypt_str(cfg.cert_private_key_enc),
                "thumbprint": cfg.cert_thumbprint,
            }
            if cfg.cert_public_pem:
                certificate["public_certificate"] = cfg.cert_public_pem
            return cls(
                cfg.tenant_id, cfg.client_id, certificate=certificate, fingerprint=fp
            )
        if not cfg.client_secret_enc:
            raise GraphError(
                "Client-secret authentication is selected but no secret is "
                "stored. Enter one on the Tenant page."
            )
        return cls(
            cfg.tenant_id,
            cfg.client_id,
            client_secret=decrypt_str(cfg.client_secret_enc),
            fingerprint=fp,
        )

    # ------------------------------------------------------------------
    # Token acquisition
    # ------------------------------------------------------------------

    def acquire_token(self) -> TokenInfo:
        """Acquire (or reuse cached) an access token for Graph.

        Raises GraphError with a user-readable message on failure.
        """
        # MSAL caches internally; this returns a cached token if valid.
        result: dict[str, Any] = self._app.acquire_token_for_client(
            scopes=GRAPH_SCOPE
        )
        if "access_token" not in result:
            err = result.get("error", "unknown_error")
            desc = result.get("error_description", "")
            raise GraphError(f"Token acquisition failed ({err}): {desc}".strip())

        expires_in = int(result.get("expires_in", 3600))
        expires_at = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(
            seconds=expires_in
        )
        return TokenInfo(access_token=result["access_token"], expires_at=expires_at)

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def send_mime(self, sender: str, raw_mime: bytes) -> None:
        """Send a raw RFC 5322 message as `sender` via Graph.

        Graph accepts raw MIME when the request body is a base64-encoded
        string posted with content-type `text/plain`. We use the
        `sendMail` action with a message reference — see:
        https://learn.microsoft.com/en-us/graph/api/user-sendmail
        For raw MIME we POST to the same endpoint with a different body.
        We prefer the raw path to preserve headers exactly as the client
        composed them (DKIM, Message-ID, etc.).
        """
        token = self.acquire_token().access_token
        url = GRAPH_SEND_MAIL_URL.format(sender=_encode_sender(sender))
        encoded = base64.b64encode(raw_mime).decode("ascii")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "text/plain",
        }
        try:
            with httpx.Client(timeout=GRAPH_HTTP_TIMEOUT_SECONDS) as client:
                resp = client.post(url, headers=headers, content=encoded)
        except httpx.HTTPError as exc:
            # Transport-level failure (timeout, connection reset, DNS):
            # transient by nature, worth retrying.
            raise GraphError(
                f"HTTP error calling Graph: {exc}", transient=True
            ) from exc

        if resp.status_code == 202:
            return  # success, as documented for sendMail

        status = resp.status_code
        # Surface the most useful part of the error to the caller.
        try:
            body = resp.json()
            detail = (
                body.get("error", {}).get("message")
                or body.get("error_description")
                or resp.text
            )
        except ValueError:
            detail = resp.text or f"HTTP {status}"

        # 429 (throttling) and 5xx are transient; honour Retry-After when
        # the server advises one. Everything else (401/403/404/550-style)
        # is permanent and should burn a retry towards DEAD.
        transient = status == 429 or 500 <= status < 600
        retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
        raise GraphError(
            f"Graph sendMail failed ({status}): {detail}",
            status_code=status,
            retry_after=retry_after,
            transient=transient,
        )


def _encode_sender(sender: str) -> str:
    """URL-encode the sender for inclusion in the Graph path.

    Graph accepts the UPN or the object id. httpx will percent-encode
    but we keep the slash-safe form explicit to avoid surprises.
    """
    from urllib.parse import quote
    return quote(sender, safe="@")
