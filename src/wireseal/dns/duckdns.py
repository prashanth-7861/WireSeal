"""DuckDNS HTTPS updater with vault-sourced SecretBytes token.

Security properties enforced by this module:
  - DNS-03: Token is typed as SecretBytes and never logged, repr'd, printed,
    or passed as a subprocess argument. The raw token string is used only
    to build the URL in memory and is not stored after the request.
  - DNS-04: HTTPS only with ssl.create_default_context() (certificate
    verification enabled). No HTTP fallback. Response body must be exactly
    'OK'; any other response raises DuckDNSError.
  - DNS-05: update_dns() contains no scheduling logic. It is a pure callable
    that platform adapters (Phase 2: cron, launchd, Task Scheduler) invoke
    on their own schedule. Importing this module has no side effects.

Usage:
    from wireseal.dns.duckdns import update_dns
    from wireseal.security.secret_types import SecretBytes

    token = SecretBytes(bytearray(b"my-duckdns-token"))
    result = update_dns("myhome", token, "93.184.216.34")
    # result["success"] is True on OK response
"""

from __future__ import annotations

import ssl
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..security.secret_types import SecretBytes

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DuckDNSError(Exception):
    """Raised on any DuckDNS update failure.

    Covers: unexpected response body (not 'OK'), network errors, timeouts,
    and SSL certificate verification failures.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _redact(url: str) -> str:
    """Return *url* with the ``token=`` query parameter value replaced by ``***``.

    DNS-03: The DuckDNS API requires the token in the query string (no
    Authorization header alternative exists per the DuckDNS spec). This helper
    MUST be used whenever the URL is passed to any logger, audit entry, or
    error message so the token never appears in logs or proxies.

    Example::

        _redact("https://www.duckdns.org/update?domains=x&token=abc123&ip=1.2.3.4")
        # -> "https://www.duckdns.org/update?domains=x&token=***&ip=1.2.3.4"
    """
    return urllib.parse.re.sub(  # type: ignore[attr-defined]
        r"((?:^|[&?])token=)[^&]*",
        r"\1***",
        url,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def update_dns(domain: str, token: "SecretBytes", ip: str) -> dict:
    """Update a DuckDNS record with the given IP address.

    Sends an HTTPS request to https://www.duckdns.org/update with the
    provided domain, token, and IP. The token is sourced from the vault as
    SecretBytes and is never logged or passed to a subprocess.

    DNS-03: token parameter is SecretBytes -- never a plain str in the
            function signature. The raw string is used only to build the
            URL and is not retained after the request.
    DNS-04: HTTPS with ssl.create_default_context(). Response body must be
            exactly 'OK'. Non-OK responses raise DuckDNSError.
    DNS-05: No scheduling logic here. Platform adapters call this function.

    Args:
        domain: DuckDNS subdomain (without .duckdns.org suffix).
        token:  SecretBytes containing the DuckDNS API token from the vault.
        ip:     Public IPv4 address string to set for the domain.

    Returns:
        A result dict with keys:
          - success (bool): True if DuckDNS returned 'OK'.
          - domain (str): The domain that was updated.
          - ip (str): The IP address that was set.
          - timestamp (str): ISO 8601 UTC timestamp of the attempt.
          - error (str | None): Error message if success is False, else None.

    Raises:
        DuckDNSError: If the response body is not 'OK' or a network/SSL
                      error occurs. The result dict is always populated
                      before raising so callers can pass it to audit.log().
    """
    # DNS-03: extract raw token bytes in memory only; never store or log
    # SecretBytes exposes the bytearray via expose_secret(); decode to str.
    token_str = bytes(token.expose_secret()).decode("ascii")

    params = urllib.parse.urlencode({
        "domains": domain,
        "token": token_str,
        "ip": ip,
        "verbose": "false",
    })
    url = f"https://www.duckdns.org/update?{params}"

    result: dict = {
        "success": False,
        "domain": domain,
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error": None,
    }

    try:
        # DNS-04: HTTPS + cert verification via ssl.create_default_context()
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, context=ctx, timeout=10) as resp:
            body = resp.read().decode("ascii", errors="replace").strip()

        if body != "OK":
            # DNS-04: response must be exactly 'OK'
            # Truncate body to 20 chars to avoid leaking token fragments
            safe_prefix = body[:20]
            exc = DuckDNSError(
                f"DuckDNS returned unexpected response (not 'OK'): {safe_prefix!r}"
            )
            result["error"] = str(exc)
            raise exc

        result["success"] = True
        result["error"] = None

    except DuckDNSError:
        raise
    except Exception as exc:
        err_msg = str(exc)
        result["error"] = err_msg
        raise DuckDNSError(f"DuckDNS update failed: {err_msg}") from exc

    finally:
        # Wipe the local token string reference -- best effort for str objects
        # (Python strings are immutable; we can only del the reference)
        del token_str, url, params

    return result
