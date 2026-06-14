"""Outbound notification dispatch: ntfy, webhook, and SMTP email.

Best-effort fan-out: a channel failure is logged and collected but never
raised to the caller, so emitting a notification can never break the action
that triggered it. All network calls use stdlib only (no new dependency) with
bounded timeouts.

Config shape (lives in the vault under ``backup``-style cache key
``notifications``)::

    {
      "enabled": true,
      "events": { "client_connect": true, "unlock_failed": true, ... },
      "channels": {
        "ntfy":    {"enabled": true, "url": "https://ntfy.sh", "topic": "x", "token": ""},
        "webhook": {"enabled": false, "url": "https://..."},
        "smtp":    {"enabled": false, "host": "", "port": 587,
                    "user": "", "pass": "", "from": "", "to": ""}
      }
    }

Secrets (``ntfy.token``, ``smtp.pass``) live only in the vault and are redacted
by the API layer before responses leave the process.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("wireseal.notify")

# Canonical event keys. The UI renders a checkbox per event.
EVENTS: tuple[str, ...] = (
    "client_connect",
    "unlock_failed",
    "backup_done",
    "backup_failed",
    "ttl_expiring",
    "tamper_detected",
)

_TIMEOUT = 8
_NTFY_PRIORITY = {"low": "2", "default": "3", "high": "5"}


def _check_scheme(url: str) -> None:
    """Block non-HTTP(S) schemes (file://, ftp://, data:, …) — admin URLs must
    be web endpoints. Private/LAN hosts are intentionally allowed (self-hosted
    ntfy is common), but a local-file or gopher scheme is never legitimate."""
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got {scheme!r}")


def _post(url: str, data: bytes, headers: dict[str, str]) -> None:
    _check_scheme(url)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (admin-supplied web URL)
        resp.read(1024)  # drain a little; ignore body


def _send_ntfy(ch: dict, title: str, body: str, priority: str) -> None:
    topic = (ch.get("topic") or "").strip()
    if not topic:
        raise ValueError("ntfy topic is empty")
    base = (ch.get("url") or "https://ntfy.sh").rstrip("/")
    headers = {
        "Title": title,
        "Content-Type": "text/plain; charset=utf-8",
        "Priority": _NTFY_PRIORITY.get(priority, "3"),
    }
    token = (ch.get("token") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    _post(f"{base}/{topic}", body.encode("utf-8"), headers)


def _send_webhook(ch: dict, event: str, title: str, body: str) -> None:
    url = (ch.get("url") or "").strip()
    if not url:
        raise ValueError("webhook url is empty")
    payload = json.dumps(
        {"event": event, "title": title, "body": body}, ensure_ascii=False
    ).encode("utf-8")
    _post(url, payload, {"Content-Type": "application/json", "User-Agent": "WireSeal"})


def _send_email(ch: dict, title: str, body: str) -> None:
    host = (ch.get("host") or "").strip()
    to_addr = (ch.get("to") or "").strip()
    if not host or not to_addr:
        raise ValueError("smtp host/to is empty")
    # SEC (F5): use the modern SMTP policy and strip CR/LF from address fields
    # so a stored value cannot inject extra headers (e.g. a hidden Bcc).
    from email.policy import SMTP as _SMTP_POLICY
    _strip = lambda s: s.replace("\r", "").replace("\n", "")
    from_addr = _strip((ch.get("from") or ch.get("user") or "wireseal@localhost").strip())
    msg = EmailMessage(policy=_SMTP_POLICY)
    msg["Subject"] = _strip(title)
    msg["From"] = from_addr
    msg["To"] = _strip(to_addr)
    msg.set_content(body)
    port = int(ch.get("port") or 587)
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        user = (ch.get("user") or "").strip()
        if user:
            smtp.login(user, ch.get("pass") or "")
        smtp.send_message(msg)


def notify(
    cfg: dict | None,
    event: str,
    title: str,
    body: str,
    priority: str = "default",
    force: bool = False,
) -> dict:
    """Fan out *event* to every enabled channel whose event flag is set.

    Args:
        cfg: notifications config dict (from the vault cache).
        event: one of :data:`EVENTS` (or any string when ``force``).
        title/body: message content.
        priority: ``low`` | ``default`` | ``high`` (ntfy only).
        force: bypass the per-event flag (used by the "send test" action).

    Returns:
        ``{"sent": [channel...], "errors": ["channel: msg"...]}``. Never raises.
    """
    result: dict = {"sent": [], "errors": []}
    if not cfg or not cfg.get("enabled"):
        return result
    if not force and not cfg.get("events", {}).get(event, False):
        return result

    channels = cfg.get("channels", {}) or {}
    senders = (
        ("ntfy", lambda c: _send_ntfy(c, title, body, priority)),
        ("webhook", lambda c: _send_webhook(c, event, title, body)),
        ("smtp", lambda c: _send_email(c, title, body)),
    )
    for name, fn in senders:
        ch = channels.get(name, {}) or {}
        if not ch.get("enabled"):
            continue
        try:
            fn(ch)
            result["sent"].append(name)
        except (urllib.error.URLError, OSError, ValueError, smtplib.SMTPException) as exc:
            # SEC (F2): log full detail server-side, but return only a generic
            # message so SMTP banners / host info don't leak to the dashboard.
            log.warning("notify channel %s failed: %s", name, exc)
            result["errors"].append(f"{name}: send failed (see server log)")
        except Exception as exc:  # never let a channel bug break the caller
            log.warning("notify channel %s unexpected error: %s", name, exc)
            result["errors"].append(f"{name}: send failed (see server log)")
    return result
