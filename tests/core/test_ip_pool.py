"""Unit tests for IP pool management.

Tests verify:
  - Sequential allocation starts at .2 (server is .1)
  - Second allocation gives .3
  - Released IPs are immediately available for reuse
  - Pre-populated allocation is skipped during allocate()
  - Non-RFC-1918 subnets raise ValueError
  - Pool exhaustion raises RuntimeError
"""

import pytest

from wireseal.core.ip_pool import IPPool


class TestIPPoolInitialization:
    """Tests for IPPool initialization and subnet validation."""

    def test_server_ip_is_dot_one(self):
        """For a /24 subnet, server IP is the .1 address."""
        pool = IPPool("10.0.0.0/24")
        assert pool.server_ip == "10.0.0.1"

    def test_server_ip_for_172_subnet(self):
        """Server IP for 172.16.0.0/24 is 172.16.0.1."""
        pool = IPPool("172.16.0.0/24")
        assert pool.server_ip == "172.16.0.1"

    def test_server_ip_for_192_168_subnet(self):
        pool = IPPool("192.168.1.0/24")
        assert pool.server_ip == "192.168.1.1"

    def test_rejects_non_rfc1918_subnet(self):
        """Public subnet 8.8.8.0/24 raises ValueError."""
        with pytest.raises(ValueError, match="RFC 1918"):
            IPPool("8.8.8.0/24")

    def test_rejects_public_subnet_google_dns(self):
        """8.8.8.0/24 (Google DNS public range) raises ValueError.

        NOTE: Python 3.11+ expanded is_private to include more ranges (e.g.,
        203.0.113.0/24 is now considered private). We use 8.8.8.0/24 which
        is a well-known public range that is_private=False in all Python versions.
        """
        with pytest.raises(ValueError):
            IPPool("8.8.8.0/24")

    def test_accepts_host_bits_in_subnet(self):
        """IPPool accepts host bits in the subnet (strict=False behavior)."""
        # 10.0.0.1/24 has host bits set but is silently masked to 10.0.0.0/24
        pool = IPPool("10.0.0.1/24")
        assert pool.server_ip == "10.0.0.1"


class TestIPPoolAllocation:
    """Tests for sequential IP allocation."""

    def test_sequential_allocation_starts_at_dot_two(self):
        """First allocation gives .2 (server occupies .1)."""
        pool = IPPool("10.0.0.0/24")
        ip = pool.allocate("alice")
        assert ip == "10.0.0.2"

    def test_second_allocation_is_dot_three(self):
        """Two sequential allocations give .2 then .3."""
        pool = IPPool("10.0.0.0/24")
        ip1 = pool.allocate("alice")
        ip2 = pool.allocate("bob")
        assert ip1 == "10.0.0.2"
        assert ip2 == "10.0.0.3"

    def test_allocated_ips_are_tracked(self):
        """is_allocated() returns True for allocated IPs."""
        pool = IPPool("10.0.0.0/24")
        ip = pool.allocate("alice")
        assert pool.is_allocated(ip)

    def test_unallocated_ip_is_not_tracked(self):
        """is_allocated() returns False for IPs not yet allocated."""
        pool = IPPool("10.0.0.0/24")
        assert not pool.is_allocated("10.0.0.2")

    def test_server_ip_never_allocated(self):
        """The server IP (.1) is never returned by allocate()."""
        pool = IPPool("10.0.0.0/24")
        allocated = [pool.allocate(f"client-{i}") for i in range(5)]
        assert pool.server_ip not in allocated


class TestIPPoolRelease:
    """Tests for IP release and reuse."""

    def test_release_allows_reuse(self):
        """After releasing .2, the next allocate returns .2 again."""
        pool = IPPool("10.0.0.0/24")
        ip = pool.allocate("alice")
        assert ip == "10.0.0.2"
        pool.release(ip)
        ip2 = pool.allocate("bob")
        assert ip2 == "10.0.0.2"

    def test_release_non_allocated_ip_is_noop(self):
        """Releasing an IP that isn't allocated must not raise."""
        pool = IPPool("10.0.0.0/24")
        pool.release("10.0.0.99")  # Not allocated -- must be a no-op

    def test_release_removes_from_allocation(self):
        """After release, is_allocated() returns False."""
        pool = IPPool("10.0.0.0/24")
        ip = pool.allocate("alice")
        pool.release(ip)
        assert not pool.is_allocated(ip)


class TestIPPoolCollisionPrevention:
    """Tests for IP-02: collision prevention."""

    def test_collision_prevention_via_load_state(self):
        """Pre-populating .2 via load_state causes allocate() to return .3."""
        pool = IPPool("10.0.0.0/24")
        # Pre-populate .2 as if loaded from vault state
        pool.load_state({"10.0.0.2": "existing-client"})
        ip = pool.allocate("new-client")
        assert ip == "10.0.0.3", f"Expected .3, got {ip}"

    def test_get_allocated_returns_copy(self):
        """get_allocated() returns a copy, not a reference to internal state."""
        pool = IPPool("10.0.0.0/24")
        pool.allocate("alice")
        allocated = pool.get_allocated()
        # Mutating the returned copy must not affect the pool
        allocated.clear()
        assert pool.is_allocated("10.0.0.2")

    def test_get_client_ip_reverse_lookup(self):
        """get_client_ip() returns the correct IP for a given client name."""
        pool = IPPool("10.0.0.0/24")
        pool.allocate("alice")
        assert pool.get_client_ip("alice") == "10.0.0.2"

    def test_get_client_ip_returns_none_for_unknown(self):
        """get_client_ip() returns None for a client with no allocation."""
        pool = IPPool("10.0.0.0/24")
        assert pool.get_client_ip("nobody") is None


class TestIPPoolExhaustion:
    """Tests for IP pool exhaustion (RuntimeError)."""

    def test_exhausted_pool_raises(self):
        """A /30 subnet has 2 host addresses (server=.1, client=.2).

        After allocating .2, the pool is exhausted and the next allocate must raise.

        /30 subnet:
          Network:   10.0.0.0
          Server:    10.0.0.1
          Client:    10.0.0.2
          Broadcast: 10.0.0.3 (not a host)
          So 1 available client IP.
        """
        pool = IPPool("10.0.0.0/30")
        pool.allocate("only-client")  # Takes .2

        with pytest.raises(RuntimeError, match="exhausted"):
            pool.allocate("no-room")

    def test_subnet_str_property(self):
        """subnet_str returns canonical CIDR string for the pool."""
        pool = IPPool("10.0.0.0/24")
        assert pool.subnet_str == "10.0.0.0/24"
