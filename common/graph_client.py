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
import logging
from dataclasses import dataclass
from typing import Any

import httpx
import msal

from .constants import (
    GRAPH_AUTHORITY_TEMPLATE,
    GRAPH_HTTP_TIMEOUT_SECONDS,
    GRAPH_SCOPE,
    GRAPH_SEND_MAIL_URL,
)

_log = logging.getLogger("relay.graph")


class GraphError(RuntimeError):
    """Raised for token or Graph API failures."""


@dataclass(slots=True)
class TokenInfo:
    access_token: str
    expires_at: _dt.datetime


class GraphClient:
    """Thin, cacheable Graph client for a single tenant configuration.

    A new instance should be built whenever the tenant config changes.
    The relay rebuilds on every queue processing loop when it detects
    a config update; callers can cheaply check `.is_for(tenant_id,
    client_id)` before reusing an existing client.
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        if not tenant_id or not client_id or not client_secret:
            raise GraphError(
                "Tenant configuration is incomplete. Configure Entra ID "
                "settings in the UI before sending mail."
            )
        self._tenant_id = tenant_id
        self._client_id = client_id
        authority = GRAPH_AUTHORITY_TEMPLATE.format(tenant_id=tenant_id)
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority,
        )

    def is_for(self, tenant_id: str, client_id: str) -> bool:
        return tenant_id == self._tenant_id and client_id == self._client_id

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
            raise GraphError(f"HTTP error calling Graph: {exc}") from exc

        if resp.status_code == 202:
            return  # success, as documented for sendMail

        # Surface the most useful part of the error to the caller.
        try:
            body = resp.json()
            detail = (
                body.get("error", {}).get("message")
                or body.get("error_description")
                or resp.text
            )
        except ValueError:
            detail = resp.text or f"HTTP {resp.status_code}"

        raise GraphError(
            f"Graph sendMail failed ({resp.status_code}): {detail}"
        )


def _encode_sender(sender: str) -> str:
    """URL-encode the sender for inclusion in the Graph path.

    Graph accepts the UPN or the object id. httpx will percent-encode
    but we keep the slash-safe form explicit to avoid surprises.
    """
    from urllib.parse import quote
    return quote(sender, safe="@")
