"""IP pool manager for WireGuard VPN subnet allocation.

Manages IP address allocation within a configurable VPN subnet.
Only RFC 1918 private ranges are accepted (IP-01).
Server always receives the first host address (.1).
Clients receive sequential IPs starting from .2 (IP-02).
Released IPs are immediately available for reuse (IP-03).
"""

import ipaddress


class IPPool:
    """Manages VPN IP address allocation within a subnet.

    The server always receives the first host address in the subnet (e.g., .1
    for /24). Clients are assigned sequential IPs starting from the second host
    address (e.g., .2). Released IPs are immediately available for reuse.

    Only RFC 1918 private address ranges are accepted as subnets.

    Example:
        pool = IPPool('10.0.0.0/24')
        pool.server_ip   # '10.0.0.1'
        ip = pool.allocate('alice')  # '10.0.0.2'
        pool.release(ip)
    """

    def __init__(self, subnet: str) -> None:
        """Initialize the IP pool for a given subnet.

        Args:
            subnet: CIDR notation subnet string. Host bits are silently masked
                (e.g., '10.0.0.1/24' is treated as '10.0.0.0/24').

        Raises:
            ValueError: If the subnet is not an RFC 1918 private range.
        """
        # strict=False allows user-friendly input with host bits set (e.g., 10.0.0.1/24)
        self.network = ipaddress.ip_network(subnet, strict=False)

        if not self.network.is_private:
            raise ValueError(
                f"Subnet {subnet} is not an RFC 1918 private range. "
                "Use a private range such as 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16."
            )

        # Server always gets the first host address (.1 for /24)
        self.server_ip: str = str(next(self.network.hosts()))

        # ip_string -> client_name mapping (IP-02: conflict detection)
        self._allocated: dict[str, str] = {}

    def load_state(self, allocated: dict[str, str]) -> None:
        """Restore allocation state from persisted vault state.

        Args:
            allocated: Previously persisted dict of {ip_string: client_name}.
                A copy is made to avoid aliasing.
        """
        self._allocated = dict(allocated)

    def allocate(self, client_name: str) -> str:
        """Allocate the next available IP address to a client.

        Skips the server IP and any already-allocated IPs.
        Sequential allocation from .2 onward (IP-01, IP-02).

        Args:
            client_name: Name/identifier of the client receiving the IP.

        Returns:
            The allocated IP address string (e.g., '10.0.0.2').

        Raises:
            RuntimeError: If no IPs are available in the pool.
        """
        for host in self.network.hosts():
            ip_str = str(host)
            # Skip the server IP (always .1)
            if ip_str == self.server_ip:
                continue
            # Skip already-allocated IPs (IP-02: conflict prevention)
            if ip_str in self._allocated:
                continue
            # First free IP: allocate it
            self._allocated[ip_str] = client_name
            return ip_str

        raise RuntimeError(f"IP pool exhausted for subnet {self.network}")

    def release(self, ip: str) -> None:
        """Release an IP address immediately (IP-03: no grace period).

        If the IP is not currently allocated, this is a no-op.

        Args:
            ip: The IP address string to release.
        """
        self._allocated.pop(ip, None)

    def is_allocated(self, ip: str) -> bool:
        """Check if an IP address is currently allocated.

        Args:
            ip: The IP address string to check.

        Returns:
            True if the IP is allocated, False otherwise.
        """
        return ip in self._allocated

    def get_client_ip(self, client_name: str) -> str | None:
        """Reverse lookup: find the IP allocated to a client by name.

        Args:
            client_name: The client name to look up.

        Returns:
            The allocated IP string, or None if the client has no allocation.
        """
        for ip_str, name in self._allocated.items():
            if name == client_name:
                return ip_str
        return None

    def get_allocated(self) -> dict[str, str]:
        """Return a copy of the allocation table for vault serialization.

        Returns:
            A copy of {ip_string: client_name} dict.
        """
        return dict(self._allocated)

    @property
    def subnet_str(self) -> str:
        """Canonical CIDR string for this pool's subnet."""
        return str(self.network)
