"""Pre-apply WireGuard config validator.

All validation functions raise ValueError with precise error messages including:
  - The field name
  - The invalid character (where applicable)
  - The exact position (where applicable)

This "compiler-quality" error reporting is a locked design decision: legitimate
users need to know exactly what is wrong to fix it quickly.

CONFIG-02: Validates all fields before any config is rendered or written.
CONFIG-06: Client names: alphanumeric + hyphens only, max 32 chars.
"""

import base64
import binascii
import ipaddress
import re
from typing import Any

# ---------------------------------------------------------------------------
# Character-level validators
# ---------------------------------------------------------------------------

_CLIENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9-]{1,32}$")
_INI_INJECTION_PATTERN = re.compile(r"[\[\]=\n\r]")


def validate_client_name(name: str) -> None:
    """Validate a WireGuard client name.

    Rules (CONFIG-06):
      - Alphanumeric characters and hyphens only: [a-zA-Z0-9-]
      - Between 1 and 32 characters inclusive
      - Empty names rejected before length check

    Args:
        name: Client name to validate.

    Raises:
        ValueError: With exact position of the first invalid character.
    """
    if not name:
        raise ValueError("Client name cannot be empty")

    if len(name) > 32:
        raise ValueError(
            f"Client name '{name}' exceeds 32-character limit ({len(name)} chars)"
        )

    for i, ch in enumerate(name):
        if not (ch.isalnum() or ch == "-"):
            raise ValueError(
                f"Client name '{name}' contains invalid character '{ch}' at position {i}"
            )


def validate_wg_key(key: str, field_name: str) -> None:
    """Validate a WireGuard base64-encoded key (Curve25519 public/private or PSK).

    A valid WireGuard key is exactly 44 characters of base64 encoding a 32-byte value.

    Args:
        key:        44-character base64 string.
        field_name: Name of the field (used in error messages).

    Raises:
        ValueError: If the key is the wrong length, invalid base64, or not 32 bytes.
    """
    if len(key) != 44:
        raise ValueError(
            f"Field '{field_name}': expected 44-character base64 key, got {len(key)} characters"
        )

    try:
        decoded = base64.b64decode(key, validate=True)
    except binascii.Error as e:
        raise ValueError(
            f"Field '{field_name}': invalid base64 encoding -- {e}"
        ) from None

    if len(decoded) != 32:
        raise ValueError(
            f"Field '{field_name}': key decodes to {len(decoded)} bytes, expected 32"
        )


def validate_port(port: int, field_name: str = "port") -> None:
    """Validate a WireGuard listen port.

    Valid range: 1024-65535 (unprivileged ports only; well-known ports < 1024 are rejected).

    Args:
        port:       Port number to validate.
        field_name: Name of the field (used in error messages).

    Raises:
        ValueError: If port is outside 1024-65535.
    """
    if not (1024 <= port <= 65535):
        raise ValueError(
            f"Field '{field_name}': port {port} outside valid range 1024-65535"
        )


def validate_subnet(subnet: str, field_name: str = "subnet") -> None:
    """Validate a VPN subnet in CIDR notation.

    The subnet must be a valid IP network in strict mode (no host bits set)
    and must be an RFC 1918 private range.

    Args:
        subnet:     CIDR subnet string (e.g., "10.0.0.0/24").
        field_name: Name of the field (used in error messages).

    Raises:
        ValueError: If the subnet is invalid or not RFC 1918.
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        raise ValueError(f"Field '{field_name}': invalid subnet '{subnet}' -- {e}") from None

    if not net.is_private:
        raise ValueError(
            f"Field '{field_name}': subnet '{subnet}' is not an RFC 1918 private range"
        )


def validate_ip(ip: str, subnet: str, field_name: str = "ip") -> None:
    """Validate an IP address is valid, RFC 1918, and within the given subnet.

    Args:
        ip:         IP address string (e.g., "10.0.0.2").
        subnet:     CIDR subnet string the IP must be within (e.g., "10.0.0.0/24").
        field_name: Name of the field (used in error messages).

    Raises:
        ValueError: If the IP is invalid, not RFC 1918, or not in the subnet.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(f"Field '{field_name}': invalid IP address '{ip}' -- {e}") from None

    if not addr.is_private:
        raise ValueError(
            f"Field '{field_name}': IP address '{ip}' is not an RFC 1918 private address"
        )

    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        raise ValueError(
            f"Field '{field_name}': subnet '{subnet}' is invalid -- {e}"
        ) from None

    if addr not in net:
        raise ValueError(
            f"Field '{field_name}': IP address '{ip}' is not within subnet '{subnet}'"
        )


def validate_no_injection(value: str, field_name: str) -> None:
    """Validate a string does not contain INI-injection characters.

    The WireGuard config format is INI-based. These characters break parsing:
      - '[' and ']': section headers
      - '=': key-value separator
      - '\\n' and '\\r': line terminators (allow multi-value injection)

    Args:
        value:      String to check.
        field_name: Name of the field (used in error messages).

    Raises:
        ValueError: With the offending character and its position.
    """
    match = _INI_INJECTION_PATTERN.search(value)
    if match:
        char = match.group(0)
        pos = match.start()
        raise ValueError(
            f"Field '{field_name}': contains INI-injection character '{repr(char)}' at position {pos}"
        )


def validate_allowed_ips(allowed_ips: str, field_name: str = "AllowedIPs") -> None:
    """Validate an AllowedIPs string (comma-separated CIDR list).

    Args:
        allowed_ips: Comma-separated CIDR entries (e.g., "10.0.0.2/32,192.168.1.0/24").
        field_name:  Name of the field (used in error messages).

    Raises:
        ValueError: If any entry is not a valid CIDR network.
    """
    entries = [e.strip() for e in allowed_ips.split(",")]
    for entry in entries:
        if not entry:
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as e:
            raise ValueError(
                f"Field '{field_name}': invalid CIDR entry '{entry}' -- {e}"
            ) from None


# ---------------------------------------------------------------------------
# Composite validators
# ---------------------------------------------------------------------------


def validate_server_config(config: dict[str, Any]) -> None:
    """Validate all fields in a server config dict before rendering.

    Checks server private key, port, subnet, and all client fields.
    The server public key is not validated here (not available at render time).

    Args:
        config: Dict with keys: private_key, public_key, port, subnet, clients.
                Each client dict has: name, public_key, psk, ip.

    Raises:
        ValueError: On the first field that fails validation.
    """
    # Server private key
    if config.get("private_key"):
        validate_wg_key(config["private_key"], "server_private_key")

    # Server port
    validate_port(config["port"], "server_port")

    # Server subnet
    subnet = config["subnet"]
    validate_subnet(subnet, "server_subnet")

    # Client records
    for client in config.get("clients", []):
        validate_client_name(client["name"])
        validate_no_injection(client["name"], f"client[{client['name']}].name")
        validate_wg_key(client["public_key"], f"client[{client['name']}].public_key")
        validate_wg_key(client["psk"], f"client[{client['name']}].psk")
        validate_ip(client["ip"], subnet, f"client[{client['name']}].ip")


def validate_client_config(config: dict[str, Any]) -> None:
    """Validate all fields in a client config dict before rendering.

    Args:
        config: Dict with keys: private_key, psk, ip, dns_server,
                server_public_key, endpoint.

    Raises:
        ValueError: On the first field that fails validation.
    """
    # Client private key
    validate_wg_key(config["private_key"], "client_private_key")

    # PSK
    validate_wg_key(config["psk"], "psk")

    # Client IP (validate it's a valid private IP; no subnet check here -- subnet not known)
    try:
        addr = ipaddress.ip_address(config["ip"])
    except ValueError as e:
        raise ValueError(f"Field 'client_ip': invalid IP address '{config['ip']}' -- {e}") from None
    if not addr.is_private:
        raise ValueError(f"Field 'client_ip': '{config['ip']}' is not an RFC 1918 private address")

    # DNS server (must be a valid IP)
    try:
        ipaddress.ip_address(config["dns_server"])
    except ValueError as e:
        raise ValueError(f"Field 'dns_server': invalid IP address '{config['dns_server']}' -- {e}") from None

    # Server public key
    validate_wg_key(config["server_public_key"], "server_public_key")

    # Endpoint: must be host:port format; validate port is numeric and in range
    endpoint = config["endpoint"]
    if ":" not in endpoint:
        raise ValueError(
            f"Field 'endpoint': '{endpoint}' is not in host:port format"
        )
    host, _, port_str = endpoint.rpartition(":")
    if not host:
        raise ValueError(f"Field 'endpoint': missing host in '{endpoint}'")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(
            f"Field 'endpoint': port '{port_str}' in '{endpoint}' is not a valid integer"
        ) from None
    validate_port(port, "endpoint.port")
