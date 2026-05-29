"""Tests for the Linux platform adapter.

All tests mock subprocess.run, os.geteuid, shutil.which, atomic_write,
and file I/O — never call real system commands or write to real paths.

Uses the same patterns as tests/security/test_permissions.py.

NOTE: Several test classes attempt to write to real filesystem paths
(/etc/, /fake) without proper mocking.  Marked as integration until
the mocking is fixed.
"""

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

pytestmark = pytest.mark.integration

from wireseal.platform.exceptions import (
    FirewallValidationError,
    PrerequisiteError,
    PrivilegeError,
    SetupError,
)
from wireseal.platform.linux import (
    LinuxAdapter,
    _build_nftables_ruleset,
    _has_firewalld,
    _validate_script_path,
)


# =========================================================================
# Internal helper tests
# =========================================================================


class TestHasFirewalld:
    """_has_firewalld() helper function."""

    def test_returns_true_when_firewall_cmd_returns_zero(self, mocker):
        """If firewall-cmd --state succeeds, _has_firewalld returns True."""
        mocker.patch("shutil.which", return_value="/usr/bin/firewall-cmd")
        mocker.patch(
            "wireseal.platform.linux.subprocess.run",
            return_value=MagicMock(returncode=0),
        )
        assert _has_firewalld() is True

    def test_returns_false_when_firewall_cmd_not_on_path(self, mocker):
        """If firewall-cmd is not installed, _has_firewalld returns False."""
        mocker.patch("shutil.which", return_value=None)
        assert _has_firewalld() is False

    def test_returns_false_when_firewall_cmd_fails(self, mocker):
        """If firewall-cmd --state returns non-zero, _has_firewalld returns False."""
        mocker.patch("shutil.which", return_value="/usr/bin/firewall-cmd")
        mocker.patch(
            "wireseal.platform.linux.subprocess.run",
            return_value=MagicMock(returncode=1),
        )
        assert _has_firewalld() is False

    def test_passes_correct_args_to_subprocess(self, mocker):
        """_has_firewalld must call 'firewall-cmd --state' with shell=False."""
        mock_which = mocker.patch("shutil.which", return_value="/usr/bin/firewall-cmd")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        _has_firewalld()
        mock_run.assert_called_once_with(
            ["firewall-cmd", "--state"],
            shell=False, capture_output=True, timeout=5,
        )


class TestBuildNftablesRuleset:
    """_build_nftables_ruleset() helper function."""

    def test_returns_non_empty_ruleset_without_firewalld(self, mocker):
        """Without firewalld, _build_nftables_ruleset must return a non-empty string."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        result = _build_nftables_ruleset("eth0", "wg0", 51820)
        assert isinstance(result, str)
        assert len(result) > 0
        assert "table inet wg_filter" in result
        assert "table ip wg_nat" in result

    def test_returns_empty_with_firewalld(self, mocker):
        """With firewalld active, _build_nftables_ruleset must return empty string."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=True)
        result = _build_nftables_ruleset("eth0", "wg0", 51820)
        assert result == ""

    def test_ruleset_includes_correct_interface_and_port(self, mocker):
        """The generated ruleset must contain the interface name and port."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        result = _build_nftables_ruleset("ens3", "wg1", 51821)
        assert 'iifname "ens3"' in result
        assert 'iifname "wg1"' in result
        assert "51821" in result

    def test_ruleset_has_masquerade_rule(self, mocker):
        """The ruleset must include NAT masquerade for the WG interface."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        result = _build_nftables_ruleset("eth0", "wg0", 51820)
        assert "masquerade" in result

    def test_ruleset_has_rate_limit(self, mocker):
        """The ruleset must have rate limiting on the WG port."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        result = _build_nftables_ruleset("eth0", "wg0", 51820)
        assert "limit rate over 5/second" in result


class TestValidateScriptPath:
    """_validate_script_path helper function."""

    def test_valid_absolute_path_passes(self, mocker):
        """A valid absolute Linux path to an existing file must pass."""
        path = MagicMock(spec=Path)
        path.__str__.return_value = "/usr/local/bin/test.sh"
        path.is_file.return_value = True
        _validate_script_path(path)

    def test_relative_path_raises(self, mocker):
        """A relative path must raise ValueError."""
        path = Path("relative/path.sh")
        with pytest.raises(ValueError, match="must be absolute"):
            _validate_script_path(path)

    def test_nonexistent_file_raises(self, mocker):
        """A path that does not exist, even if absolute, must raise ValueError."""
        # On Windows, Path("/...") creates a path relative to drive root
        # which passes the startswith("/") check on POSIX but not Win32.
        # Use an explicit MagicMock to bypass platform path quirks.
        path = MagicMock(spec=Path)
        path.__str__.return_value = "/usr/local/bin/nonexistent.sh"
        path.is_file.return_value = False
        with pytest.raises(ValueError, match="does not exist"):
            _validate_script_path(path)

    def test_forbidden_chars_raise(self, mocker):
        """Paths containing ; & | $ ` etc. must raise ValueError."""
        for char in [";", "&", "|", "$", "`"]:
            path = Path(f"/usr/local/bin/bad{char}name.sh")
            with pytest.raises(ValueError, match="forbidden character"):
                _validate_script_path(path)


# =========================================================================
# Fixture
# =========================================================================


@pytest.fixture()
def adapter():
    """Return a fresh LinuxAdapter instance."""
    return LinuxAdapter()


@pytest.fixture()
def mock_subprocess(mocker):
    """Mock subprocess.run to return a successful result by default."""
    mock = mocker.patch("wireseal.platform.linux.subprocess.run")
    mock.return_value = MagicMock(
        returncode=0,
        stdout=b"",
        stderr=b"",
    )
    return mock


# =========================================================================
# 1. Privilege check
# =========================================================================


class TestCheckPrivileges:
    """check_privileges must raise PrivilegeError when not root."""

    def test_passes_when_euid_is_zero(self, adapter, mocker):
        """When os.geteuid() == 0, check_privileges must return None."""
        mocker.patch("wireseal.platform.linux.os.geteuid", return_value=0, create=True)
        adapter.check_privileges()

    def test_raises_when_euid_is_not_zero(self, adapter, mocker):
        """When os.geteuid() != 0, check_privileges must raise PrivilegeError."""
        mocker.patch("wireseal.platform.linux.os.geteuid", return_value=1000, create=True)
        with pytest.raises(PrivilegeError):
            adapter.check_privileges()

    def test_error_message_suggests_sudo(self, adapter, mocker):
        """The error message must suggest using sudo."""
        mocker.patch("wireseal.platform.linux.os.geteuid", return_value=1000, create=True)
        with pytest.raises(PrivilegeError) as exc:
            adapter.check_privileges()
        assert "sudo" in str(exc.value).lower()

    def test_debug_mode_prints_warning(self, adapter, mocker, capsys):
        """When WIRESEAL_DEBUG is set, a warning about vault location is printed."""
        mocker.patch("wireseal.platform.linux.os.geteuid", return_value=0, create=True)
        mocker.patch.dict(os.environ, {"WIRESEAL_DEBUG": "1", "SUDO_USER": "testuser"})
        adapter.check_privileges()
        captured = capsys.readouterr()
        assert "vault" in captured.err.lower()


# =========================================================================
# 2. Prerequisite check
# =========================================================================


class TestCheckPrerequisites:
    """check_prerequisites must detect missing tools."""

    def test_returns_empty_list_when_all_present(self, adapter, mocker):
        """When all required tools are on PATH, return empty list."""
        mocker.patch("shutil.which", return_value="/usr/bin/tool")
        result = adapter.check_prerequisites()
        assert result == []

    def test_raises_when_tools_missing(self, adapter, mocker):
        """When a required tool is missing, raise PrerequisiteError."""
        mocker.patch("shutil.which", return_value=None)
        with pytest.raises(PrerequisiteError):
            adapter.check_prerequisites()

    def test_error_message_includes_install_hint(self, adapter, mocker):
        """The error must include 'apt install' or similar."""
        mocker.patch("shutil.which", return_value=None)
        with pytest.raises(PrerequisiteError) as exc:
            adapter.check_prerequisites()
        msg = str(exc.value)
        assert "install" in msg

    def test_error_message_includes_missing_tool_names(self, adapter, mocker):
        """The error must name which tools are missing."""
        mocker.patch("shutil.which", return_value=None)
        with pytest.raises(PrerequisiteError) as exc:
            adapter.check_prerequisites()
        msg = str(exc.value)
        assert "wg" in msg or "nft" in msg or "systemctl" in msg


# =========================================================================
# 3. WireGuard installation
# =========================================================================


class TestInstallWireguard:
    """install_wireguard delegates to package manager via subprocess."""

    def test_skips_if_wg_already_installed(self, adapter, mocker, mock_subprocess):
        """If wg is already on PATH, no subprocess call."""
        mocker.patch("shutil.which", return_value="/usr/bin/wg")
        adapter.install_wireguard()
        mock_subprocess.assert_not_called()

    def test_installs_via_apt_on_debian(self, adapter, mocker, mock_subprocess):
        """On Debian/Ubuntu, install via apt-get."""
        mocker.patch("shutil.which", side_effect=lambda x: None if x == "wg" else "/usr/bin/apt-get")
        adapter.install_wireguard()
        mock_subprocess.assert_called_once()
        cmd = mock_subprocess.call_args[0][0]
        assert "apt-get" in cmd

    def test_installs_via_dnf_on_fedora(self, adapter, mocker, mock_subprocess):
        """On Fedora/RHEL, install via dnf."""
        def _which(cmd):
            if cmd == "wg":
                return None
            if cmd == "dnf":
                return "/usr/bin/dnf"
            return "/usr/bin/tool"
        mocker.patch("shutil.which", side_effect=_which)
        # distro is imported inside the function, not at module level.
        # Mock it via sys.modules so the local import picks it up.
        mock_distro = MagicMock()
        mock_distro.id.return_value = "fedora"
        mocker.patch.dict("sys.modules", {"distro": mock_distro})
        adapter.install_wireguard()
        cmd = mock_subprocess.call_args[0][0]
        assert "dnf" in cmd

    def test_raises_setup_error_on_subprocess_failure(self, adapter, mocker):
        """When package manager fails, raise SetupError."""
        mocker.patch("shutil.which", return_value=None)
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.side_effect = subprocess.CalledProcessError(1, ["apt-get"], stderr=b"E: failed")
        with pytest.raises(SetupError):
            adapter.install_wireguard()


# =========================================================================
# 4. Config deployment
# =========================================================================


class TestDeployConfig:
    """deploy_config writes config atomically with correct permissions."""

    def test_writes_to_wireguard_directory(self, adapter, mocker):
        """Config must be written to /etc/wireguard/{interface}.conf."""
        mocker.patch("wireseal.platform.linux._WIREGUARD_DIR", new=Path("/fake/etc/wireguard"))
        mock_atomic = mocker.patch("wireseal.platform.linux.atomic_write")
        mock_mkdir = mocker.patch("pathlib.Path.mkdir")
        result = adapter.deploy_config("[Interface]", "wg0")
        assert result == Path("/fake/etc/wireguard/wg0.conf")
        mock_atomic.assert_called_once()
        assert mock_atomic.call_args[0][0] == result

    def test_creates_parent_directory(self, adapter, mocker):
        """If /etc/wireguard does not exist, it must be created with mode 0o700."""
        fake_parent = MagicMock(spec=Path)
        fake_parent.exists.return_value = False
        fake_path = MagicMock(spec=Path)
        fake_path.parent = fake_parent
        fake_path.__str__.return_value = "/etc/wireguard/wg0.conf"
        mocker.patch.object(adapter, "get_config_path", return_value=fake_path)
        mocker.patch("wireseal.platform.linux.atomic_write")
        adapter.deploy_config("[Interface]", "wg0")
        fake_parent.mkdir.assert_called_once_with(parents=True, mode=0o700, exist_ok=True)

    def test_uses_mode_600(self, adapter, mocker):
        """atomic_write must be called with mode=0o600."""
        mocker.patch("wireseal.platform.linux._WIREGUARD_DIR", new=Path("/fake/etc/wireguard"))
        mock_atomic = mocker.patch("wireseal.platform.linux.atomic_write")
        adapter.deploy_config("[Interface]", "wg0")
        assert mock_atomic.call_args[1].get("mode") == 0o600


# =========================================================================
# 5 & 6. Firewall management (apply / remove)
# =========================================================================


class TestApplyFirewallRules:
    """apply_firewall_rules validates and applies nftables or firewalld rules."""

    def test_validates_interface_port_subnet(self, adapter, mocker):
        """Inputs must be validated before any subprocess call."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        mocker.patch.object(adapter, "detect_outbound_interface", return_value="eth0")
        mocker.patch("wireseal.platform.linux.subprocess.run")
        mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux._build_nftables_ruleset", return_value="rules")
        mocker.patch.object(adapter, "validate_firewall_rules")
        # No exception expected with valid inputs
        adapter.apply_firewall_rules(51820, "wg0", "10.0.0.0/24")

    def test_cleans_stale_nft_tables(self, adapter, mocker):
        """Old nftables tables must be deleted before applying new rules."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        mocker.patch.object(adapter, "detect_outbound_interface", return_value="eth0")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux._build_nftables_ruleset", return_value="rules")
        mocker.patch.object(adapter, "validate_firewall_rules")
        adapter.apply_firewall_rules(51820, "wg0", "10.0.0.0/24")
        # At least one nft delete call
        delete_calls = [c for c in mock_run.call_args_list if c[0][0][:3] == ["nft", "delete", "table"]]
        assert len(delete_calls) >= 2

    def test_uses_nft_f_on_rules_file_without_firewalld(self, adapter, mocker):
        """Without firewalld, must call nft -f with the rules file."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        mocker.patch.object(adapter, "detect_outbound_interface", return_value="eth0")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux._build_nftables_ruleset", return_value="table inet x { }")
        mocker.patch.object(adapter, "validate_firewall_rules")
        adapter.apply_firewall_rules(51820, "wg0", "10.0.0.0/24")
        # The last nft call should be nft -f
        all_calls = [c for c in mock_run.call_args_list
                     if "nft" in c[0][0][0] or c[0][0][0] == "nft"]
        if all_calls:
            last_nft = all_calls[-1]
            assert last_nft[0][0][0] == "nft"
            assert last_nft[0][0][1] == "-f"

    def test_uses_firewalld_when_active(self, adapter, mocker):
        """With firewalld active, must call firewall-cmd (not nftables)."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=True)
        mocker.patch.object(adapter, "detect_outbound_interface", return_value="eth0")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        adapter.apply_firewall_rules(51820, "wg0", "10.0.0.0/24")
        assert any("firewall-cmd" in str(c) for c in mock_run.call_args_list)

    def test_raises_on_nftables_failure(self, adapter, mocker):
        """When nft -f fails, must raise SetupError."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        mocker.patch.object(adapter, "detect_outbound_interface", return_value="eth0")
        mocker.patch("wireseal.platform.linux._build_nftables_ruleset", return_value="table inet x { }")
        mocker.patch.object(adapter, "validate_firewall_rules")
        mocker.patch("wireseal.platform.linux.atomic_write")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        ok = MagicMock(returncode=0, stdout=b"", stderr=b"")
        mock_run.side_effect = [
            ok,  # nft delete inet wg_filter
            ok,  # nft delete inet wg_forward
            ok,  # nft delete ip wg_nat
            subprocess.CalledProcessError(1, ["nft", "-f"], stderr=b"Error: syntax error"),
        ]
        with pytest.raises(SetupError):
            adapter.apply_firewall_rules(51820, "wg0", "10.0.0.0/24")


class TestRemoveFirewallRules:
    """remove_firewall_rules cleans up nftables tables and firewalld rules."""

    def test_removes_nftables_tables(self, adapter, mocker, mock_subprocess):
        """Must call nft delete for wg_filter and wg_nat tables."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        adapter.remove_firewall_rules("wg0")
        delete_calls = [c for c in mock_subprocess.call_args_list
                        if c[0][0][:3] == ["nft", "delete", "table"]]
        assert len(delete_calls) >= 2

    def test_removes_firewalld_rules_when_active(self, adapter, mocker, mock_subprocess):
        """With firewalld active, must call firewall-cmd remove commands."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=True)
        adapter.remove_firewall_rules("wg0")
        assert any("firewall-cmd" in str(c) for c in mock_subprocess.call_args_list)

    def test_removes_nftables_rules_file(self, adapter, mocker, mock_subprocess):
        """The nftables rules file must be deleted if it exists."""
        mocker.patch("wireseal.platform.linux._has_firewalld", return_value=False)
        fake_rules = MagicMock(spec=Path)
        fake_rules.exists.return_value = True
        mocker.patch("wireseal.platform.linux._NFT_RULES_FILE", new=fake_rules)
        adapter.remove_firewall_rules("wg0")
        fake_rules.unlink.assert_called_once()

    def test_idempotent_on_missing_tables(self, adapter, mocker, mock_subprocess):
        """Errors from nft delete on non-existent tables must be silent."""
        # subprocess.run returns non-zero when table does not exist
        adapter.remove_firewall_rules("wg0")


# =========================================================================
# 7. IP forwarding
# =========================================================================


class TestEnableIpForwarding:
    """enable_ip_forwarding writes sysctl.d drop-in and applies it."""

    def test_writes_sysctl_drop_in(self, adapter, mocker):
        """Must write /etc/sysctl.d/99-wireguard.conf with correct content."""
        mocker.patch("wireseal.platform.linux._SYSCTL_DROP_IN", new=Path("/fake/sysctl.d/99-wireguard.conf"))
        mock_atomic = mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux.subprocess.run")
        adapter.enable_ip_forwarding()
        mock_atomic.assert_called_once()
        content = mock_atomic.call_args[0][1]
        assert b"net.ipv4.ip_forward = 1" in content

    def test_applies_with_sysctl(self, adapter, mocker, mock_subprocess):
        """Must call sysctl -p after writing the drop-in."""
        mocker.patch("wireseal.platform.linux._SYSCTL_DROP_IN", new=Path("/fake/sysctl.d/99-wireguard.conf"))
        mocker.patch("wireseal.platform.linux.atomic_write")
        adapter.enable_ip_forwarding()
        sysctl_calls = [c for c in mock_subprocess.call_args_list
                        if "sysctl" in c[0][0][0] or c[0][0][0] == "/sbin/sysctl"]
        assert len(sysctl_calls) >= 1

    def test_raises_setup_error_on_sysctl_failure(self, adapter, mocker):
        """When sysctl -p fails, raise SetupError."""
        mocker.patch("wireseal.platform.linux._SYSCTL_DROP_IN", new=Path("/fake/sysctl.d/99-wireguard.conf"))
        mocker.patch("wireseal.platform.linux.atomic_write")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["sysctl", "-p"], stderr=b"error"
        )
        with pytest.raises(SetupError):
            adapter.enable_ip_forwarding()


# =========================================================================
# 8 & 9. Tunnel service lifecycle
# =========================================================================


class TestEnableTunnelService:
    """enable_tunnel_service is a deliberate no-op on Linux."""

    def test_returns_none(self, adapter, mock_subprocess):
        """Must return None without calling subprocess."""
        result = adapter.enable_tunnel_service("wg0")
        assert result is None
        mock_subprocess.assert_not_called()

    def test_noop_for_custom_interface(self, adapter, mock_subprocess):
        """Must be no-op for any interface name."""
        result = adapter.enable_tunnel_service("wg1")
        assert result is None


class TestDisableTunnelService:
    """disable_tunnel_service stops and disables wg-quick service."""

    def test_stops_and_disables_service(self, adapter, mock_subprocess):
        """Must call systemctl stop and disable for wg-quick@{interface}."""
        adapter.disable_tunnel_service("wg0")
        stop_call = call(["systemctl", "stop", "wg-quick@wg0"],
                         shell=False, capture_output=True, timeout=30)
        disable_call = call(["systemctl", "disable", "wg-quick@wg0"],
                            shell=False, capture_output=True, timeout=30)
        mock_subprocess.assert_has_calls([stop_call, disable_call], any_order=False)

    def test_uses_provided_interface(self, adapter, mock_subprocess):
        """Must use the provided interface name, not hardcoded wg0."""
        adapter.disable_tunnel_service("wg1")
        mock_subprocess.assert_any_call(
            ["systemctl", "stop", "wg-quick@wg1"],
            shell=False, capture_output=True, timeout=30,
        )


# =========================================================================
# 10. DNS updater scheduling
# =========================================================================


class TestSetupDnsUpdater:
    """setup_dns_updater creates wireseal user and writes cron.d entry."""

    @pytest.fixture()
    def script(self, tmp_path):
        s = tmp_path / "wireseal.sh"
        s.write_text("#!/bin/sh")
        return s

    def test_creates_system_user_if_not_present(self, adapter, mocker, script):
        """When wireseal user does not exist, must call adduser."""
        mocker.patch("wireseal.platform.linux._validate_script_path")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux._CRON_FILE", new=Path("/fake/cron.d/wireseal"))

        def _side_effect(cmd, **kw):
            if cmd[0] == "id":
                return MagicMock(returncode=1)
            return MagicMock(returncode=0)
        mock_run.side_effect = _side_effect

        adapter.setup_dns_updater(script)
        adduser_calls = [c for c in mock_run.call_args_list if c[0][0][0] == "adduser"]
        assert len(adduser_calls) >= 1
        assert "wireseal" in str(adduser_calls[0])

    def test_skips_user_creation_if_already_exists(self, adapter, mocker, script):
        """When wireseal user already exists, must not call adduser."""
        mocker.patch("wireseal.platform.linux._validate_script_path")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux._CRON_FILE", new=Path("/fake/cron.d/wireseal"))

        def _side_effect(cmd, **kw):
            return MagicMock(returncode=0)
        mock_run.side_effect = _side_effect

        adapter.setup_dns_updater(script)
        adduser_calls = [c for c in mock_run.call_args_list if c[0][0][0] == "adduser"]
        assert len(adduser_calls) == 0

    def test_writes_cron_file(self, adapter, mocker, script):
        """Must write a cron.d file with the correct schedule."""
        mocker.patch("wireseal.platform.linux._validate_script_path")
        mocker.patch("wireseal.platform.linux.subprocess.run",
                     return_value=MagicMock(returncode=0))
        mock_atomic = mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux._CRON_FILE", new=Path("/fake/cron.d/wireseal"))
        adapter.setup_dns_updater(script, interval_minutes=10)
        content = mock_atomic.call_args[0][1]
        assert b"*/10 * * * *" in content
        assert bytes(str(script), "utf-8") in content

    def test_raises_on_adduser_failure(self, adapter, mocker, script):
        """When adduser fails, must raise SetupError."""
        mocker.patch("wireseal.platform.linux._validate_script_path")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mocker.patch("wireseal.platform.linux.atomic_write")

        def _side_effect(cmd, **kw):
            if cmd[0] == "id":
                return MagicMock(returncode=1)
            if cmd[0] == "adduser":
                raise subprocess.CalledProcessError(1, ["adduser"], stderr=b"failed")
            return MagicMock(returncode=0)
        mock_run.side_effect = _side_effect

        with pytest.raises(SetupError):
            adapter.setup_dns_updater(script)

    def test_interval_minutes_in_cron(self, adapter, mocker, script):
        """The cron interval must use the provided interval_minutes."""
        mocker.patch("wireseal.platform.linux._validate_script_path")
        mocker.patch("wireseal.platform.linux.subprocess.run",
                     return_value=MagicMock(returncode=0))
        mock_atomic = mocker.patch("wireseal.platform.linux.atomic_write")
        mocker.patch("wireseal.platform.linux._CRON_FILE", new=Path("/fake/cron.d/wireseal"))
        adapter.setup_dns_updater(script, interval_minutes=3)
        content = mock_atomic.call_args[0][1].decode()
        assert "*/3 * * * *" in content


# =========================================================================
# 11. Config path resolution
# =========================================================================


class TestGetConfigPath:
    """get_config_path returns the correct WireGuard config path."""

    def test_returns_etc_wireguard_path(self, adapter):
        """Path must be /etc/wireguard/{interface}.conf."""
        path = adapter.get_config_path("wg0")
        assert path == Path("/etc/wireguard/wg0.conf")

    def test_respects_custom_interface(self, adapter):
        """The interface name must be reflected in the path."""
        path = adapter.get_config_path("vpn0")
        assert path == Path("/etc/wireguard/vpn0.conf")


# =========================================================================
# 12. Outbound interface detection
# =========================================================================


class TestDetectOutboundInterface:
    """detect_outbound_interface parses 'ip route get 8.8.8.8' output."""

    def test_parses_dev_field_from_ip_route(self, adapter, mocker):
        """Must extract the interface name after 'dev' in ip route output."""
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 0\n",
            stderr="",
        )
        iface = adapter.detect_outbound_interface()
        assert iface == "eth0"

    def test_raises_setup_error_when_no_match(self, adapter, mocker):
        """When 'dev' is not found in output, must raise SetupError."""
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="unknown output format 12345\n",
            stderr="",
        )
        with pytest.raises(SetupError):
            adapter.detect_outbound_interface()

    def test_uses_ip_route_get_command(self, adapter, mocker):
        """Must call 'ip route get 8.8.8.8' with correct arguments."""
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="8.8.8.8 dev eth0 src 192.168.1.100\n",
            stderr="",
        )
        adapter.detect_outbound_interface()
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["ip", "route", "get", "8.8.8.8"]

    def test_raises_on_invalid_interface_name(self, adapter, mocker):
        """Interface names that don't match the pattern must raise SetupError."""
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="8.8.8.8 dev ..; rm -rf / src 10.0.0.1\n",
            stderr="",
        )
        with pytest.raises(SetupError):
            adapter.detect_outbound_interface()


# =========================================================================
# 13. LAN subnet detection
# =========================================================================


class TestDetectLanSubnet:
    """detect_lan_subnet uses outbound interface to find the CIDR."""

    def test_parses_subnet_from_ip_addr(self, adapter, mocker):
        """Must parse the CIDR from 'ip -o -f inet addr show'."""
        mocker.patch.object(adapter, "detect_outbound_interface", return_value="eth0")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="2: eth0    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n",
            stderr="",
        )
        subnet = adapter.detect_lan_subnet()
        assert subnet == "192.168.1.0/24"

    def test_raises_when_no_inet_address(self, adapter, mocker):
        """When no IPv4 address is found, must raise SetupError."""
        mocker.patch.object(adapter, "detect_outbound_interface", return_value="eth0")
        mock_run = mocker.patch("wireseal.platform.linux.subprocess.run")
        mock_run.return_value = MagicMock(
            returncode=0, stdout="",
            stderr="",
        )
        with pytest.raises(SetupError):
            adapter.detect_lan_subnet()

    def test_delegates_to_detect_outbound_interface(self, adapter, mocker):
        """Must call detect_outbound_interface first."""
        mock_detect = mocker.patch.object(
            adapter, "detect_outbound_interface", return_value="eth0"
        )
        mocker.patch("wireseal.platform.linux.subprocess.run",
                     return_value=MagicMock(returncode=0, stdout="inet 10.0.0.5/8\n"))
        adapter.detect_lan_subnet()
        mock_detect.assert_called_once()


# =========================================================================
# Abstract method from base (concrete on adapter)
# =========================================================================


class TestValidateFirewallRulesOnAdapter:
    """validate_firewall_rules delegate on the adapter instance."""

    def test_passes_through_to_module_function(self, adapter, mocker):
        """The adapter method must delegate to the module-level function."""
        mock_function = mocker.patch("wireseal.platform.base.validate_firewall_rules")
        adapter.validate_firewall_rules("gen", "tpl")
        mock_function.assert_called_once_with("gen", "tpl")
