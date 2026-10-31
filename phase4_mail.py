"""Gmail OAuth mail integration for Phase 4 broker-removal requests.

This module deliberately uses only the narrow Gmail ``gmail.send`` scope plus
OpenID/email identity scopes. It never asks for a Gmail password and it does
not request mailbox-wide read access.

Required local configuration (Google Cloud OAuth Web application):
    GOOGLE_CLIENT_ID=<oauth client id>
    GOOGLE_CLIENT_SECRET=<oauth client secret>
Optional:
    GOOGLE_REDIRECT_URI=http://localhost:5000/phase4/mail/callback
    GOOGLE_WORKSPACE_DOMAINS=example.edu,example.org

The OAuth token is stored only under reports/phase4/private/, which is excluded
from the shareable Phase 4 report and should remain gitignored.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional convenience only
    load_dotenv = None

if load_dotenv:
    load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
PRIVATE_DIR = REPORTS_DIR / "phase4" / "private"
TOKEN_FILE = PRIVATE_DIR / "gmail_oauth_token.json"

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
DEFAULT_REDIRECT_URI = "http://localhost:5000/phase4/mail/callback"
SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.send",
]


class MailIntegrationError(RuntimeError):
    pass


def utc_epoch() -> int:
    return int(time.time())


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    form_body: Optional[Dict[str, Any]] = None,
    timeout: float = 25.0,
) -> Tuple[int, Dict[str, Any] | None]:
    request_headers = dict(headers or {})
    data: bytes | None = None

    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        data = urlencode(form_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = Request(url, data=data, headers=request_headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read()
            if not raw:
                return int(response.status), None
            return int(response.status), json.loads(raw.decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body) if body else {}
        except Exception:
            parsed = {"raw": body}
        error_value = parsed.get("error") if isinstance(parsed, dict) else None
        if isinstance(error_value, dict):
            message = error_value.get("message") or error_value.get("status")
        else:
            message = parsed.get("error_description") or error_value if isinstance(parsed, dict) else None
        raise MailIntegrationError(
            f"Google request failed ({exc.code}): {message or body or exc.reason}"
        ) from exc
    except URLError as exc:
        raise MailIntegrationError(f"Google request failed: {exc.reason}") from exc


def _workspace_domains() -> set[str]:
    raw = os.getenv("GOOGLE_WORKSPACE_DOMAINS", "")
    return {
        value.strip().casefold()
        for value in raw.split(",")
        if value.strip()
    }


def mail_capability_for_address(email: str) -> Dict[str, Any]:
    """Describe the supported delivery path for the Phase 1 identity email."""
    value = str(email or "").strip()
    domain = value.rsplit("@", 1)[-1].casefold() if "@" in value else ""
    gmail_domains = {"gmail.com", "googlemail.com"} | _workspace_domains()
    automatic = domain in gmail_domains
    return {
        "email": value,
        "domain": domain,
        "provider": "Gmail" if automatic else (domain or "mail provider"),
        "automatic_oauth_supported": automatic,
        "manual_fallback": not automatic,
        "reason": (
            "Gmail OAuth can send from this same mailbox without collecting its password."
            if automatic
            else "No OAuth connector is configured for this mailbox provider; use the manual assisted-send fallback."
        ),
    }


def configuration() -> Dict[str, Any]:
    client_id = (os.getenv("GOOGLE_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("GOOGLE_CLIENT_SECRET") or "").strip()
    redirect_uri = (
        os.getenv("GOOGLE_REDIRECT_URI") or DEFAULT_REDIRECT_URI
    ).strip() or DEFAULT_REDIRECT_URI
    return {
        "configured": bool(client_id and client_secret),
        "client_id": client_id,
        "client_secret_present": bool(client_secret),
        "redirect_uri": redirect_uri,
        "scopes": list(SCOPES),
    }


def create_pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorization_url(*, state: str, code_challenge: str) -> str:
    cfg = configuration()
    if not cfg["configured"]:
        raise MailIntegrationError(
            "Gmail OAuth is not configured. Set GOOGLE_CLIENT_ID and "
            "GOOGLE_CLIENT_SECRET in the local .env file."
        )

    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": " ".join(cfg["scopes"]),
        "state": state,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent select_account",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return AUTH_URL + "?" + urlencode(params)


def _decorate_token(payload: Dict[str, Any]) -> Dict[str, Any]:
    token = dict(payload)
    expires_in = int(token.get("expires_in", 3600) or 3600)
    token["obtained_at"] = utc_epoch()
    token["expires_at"] = utc_epoch() + max(60, expires_in)
    return token


def _write_token(token: Dict[str, Any]) -> None:
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps(token, indent=2), encoding="utf-8")
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass


def load_token() -> Dict[str, Any] | None:
    try:
        if not TOKEN_FILE.exists():
            return None
        value = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _userinfo(access_token: str) -> Dict[str, Any]:
    status, payload = _json_request(
        USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if status != 200 or not isinstance(payload, dict):
        raise MailIntegrationError("Google did not return the connected account identity.")
    return payload


def exchange_authorization_code(*, code: str, code_verifier: str) -> Dict[str, Any]:
    cfg = configuration()
    client_secret = (os.getenv("GOOGLE_CLIENT_SECRET") or "").strip()
    if not cfg["configured"]:
        raise MailIntegrationError("Google OAuth client configuration is incomplete.")

    status, payload = _json_request(
        TOKEN_URL,
        method="POST",
        form_body={
            "client_id": cfg["client_id"],
            "client_secret": client_secret,
            "code": code,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": cfg["redirect_uri"],
        },
    )
    if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
        raise MailIntegrationError("Google did not return a usable access token.")

    token = _decorate_token(payload)
    account = _userinfo(str(token["access_token"]))
    token["account"] = {
        "email": str(account.get("email") or ""),
        "email_verified": bool(account.get("email_verified", False)),
        "name": str(account.get("name") or ""),
        "sub": str(account.get("sub") or ""),
    }
    _write_token(token)
    return token


def _refresh_token(token: Dict[str, Any]) -> Dict[str, Any]:
    cfg = configuration()
    client_secret = (os.getenv("GOOGLE_CLIENT_SECRET") or "").strip()
    refresh = str(token.get("refresh_token") or "")
    if not refresh:
        raise MailIntegrationError("The Gmail session expired. Connect Gmail again.")

    status, payload = _json_request(
        TOKEN_URL,
        method="POST",
        form_body={
            "client_id": cfg["client_id"],
            "client_secret": client_secret,
            "refresh_token": refresh,
            "grant_type": "refresh_token",
        },
    )
    if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
        raise MailIntegrationError("Gmail token refresh failed. Connect Gmail again.")

    refreshed = dict(token)
    refreshed.update(_decorate_token(payload))
    refreshed["refresh_token"] = str(payload.get("refresh_token") or refresh)
    _write_token(refreshed)
    return refreshed


def ensure_access_token() -> Dict[str, Any]:
    token = load_token()
    if not token:
        raise MailIntegrationError("No Gmail mailbox is connected.")
    if int(token.get("expires_at", 0) or 0) <= utc_epoch() + 90:
        token = _refresh_token(token)
    return token


def connection_status() -> Dict[str, Any]:
    cfg = configuration()
    token = load_token()
    account = (token or {}).get("account") or {}
    return {
        "provider": "Gmail",
        "configured": bool(cfg["configured"]),
        "connected": bool(token and (token.get("access_token") or token.get("refresh_token"))),
        "address": str(account.get("email") or ""),
        "display_name": str(account.get("name") or ""),
        "redirect_uri": cfg["redirect_uri"],
        "scopes": list(SCOPES),
        "proof_model": "gmail_send_response_plus_sent_label",
    }


def disconnect() -> None:
    try:
        TOKEN_FILE.unlink()
    except FileNotFoundError:
        pass


def _build_raw_message(
    *,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    reference: str,
) -> Tuple[str, str, str]:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message["Date"] = format_datetime(datetime.now(timezone.utc))
    sender_domain = sender.rsplit("@", 1)[-1] if "@" in sender else None
    rfc_message_id = make_msgid(domain=sender_domain)
    message["Message-ID"] = rfc_message_id
    message["X-Deleting-Footprints-Reference"] = reference
    message.set_content(body)

    raw_bytes = message.as_bytes()
    raw_encoded = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return raw_encoded, digest, rfc_message_id


def _sent_response_evidence(
    payload: Dict[str, Any],
    *,
    sender: str,
    recipient: str,
    subject: str,
    reference: str,
    message_sha256: str,
    rfc_message_id: str,
) -> Dict[str, Any]:
    labels = [str(value) for value in (payload.get("labelIds") or [])]
    verified = "SENT" in {value.upper() for value in labels}
    message_id = str(payload.get("id") or "")
    return {
        "verified": verified,
        "provider_accepted": bool(message_id),
        "provider": "Gmail API",
        "method": "gmail_api_email",
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "reference": reference,
        "sent_at": utc_now_iso(),
        "provider_message_id": message_id,
        "provider_thread_id": str(payload.get("threadId") or ""),
        "sent_item_id": message_id,
        "gmail_label_ids": labels,
        "message_sha256": message_sha256,
        "rfc_message_id": rfc_message_id,
        "web_link": "https://mail.google.com/mail/#sent",
        "proof_note": (
            "Gmail returned this exact submitted message with the SENT system label."
            if verified
            else "Gmail accepted the message, but the send response did not include the SENT label."
        ),
    }


def send_and_verify(
    *,
    recipient: str,
    subject: str,
    body: str,
    reference: str,
    expected_sender: str = "",
) -> Dict[str, Any]:
    """Send the exact approved request through Gmail and capture provider proof.

    No mailbox read scope is used. Gmail documents that the SENT system label is
    applied automatically to messages sent with users.messages.send; the send
    response contains the Message resource, including labelIds.
    """
    if not recipient or "@" not in recipient:
        raise MailIntegrationError("A valid broker/privacy contact email is required.")

    token = ensure_access_token()
    account = token.get("account") or {}
    sender = str(account.get("email") or "").strip()
    if not sender:
        raise MailIntegrationError("The connected Gmail account address is unavailable.")

    if expected_sender and sender.casefold() != str(expected_sender).strip().casefold():
        raise MailIntegrationError(
            "The connected Gmail account does not match the email supplied in Phase 1. "
            "Disconnect Gmail and connect the same account used for this scan."
        )

    raw_message, message_sha256, rfc_message_id = _build_raw_message(
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=body,
        reference=reference,
    )
    status, payload = _json_request(
        GMAIL_SEND_URL,
        method="POST",
        headers={"Authorization": f"Bearer {token['access_token']}"},
        json_body={"raw": raw_message},
    )
    if status != 200 or not isinstance(payload, dict) or not payload.get("id"):
        raise MailIntegrationError(f"Gmail did not accept the email (HTTP {status}).")

    return _sent_response_evidence(
        payload,
        sender=sender,
        recipient=recipient,
        subject=subject,
        reference=reference,
        message_sha256=message_sha256,
        rfc_message_id=rfc_message_id,
    )
