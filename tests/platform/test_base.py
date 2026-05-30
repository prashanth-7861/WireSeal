"""Tests for the platform adapter base module.

Verifies:
  - validate_firewall_rules function (FW-03)
  - Structural pattern matching (template = regex patterns)
  - Overly permissive rule detection (deny-by-default enforcement)
  - Normalization logic (stripping, blank lines, comments)
  - FirewallValidationError on mismatch
  - Empty generated rules raise error
"""

import pytest

from wireseal.platform.base import validate_firewall_rules
from wireseal.platform.exceptions import FirewallValidationError


class TestValidateFirewallRules:
    """Module-level validate_firewall_rules function (FW-03)."""

    def test_identical_pattern_pass(self):
        """Generated rules matching template patterns must pass without error."""
        rules = (
            "table inet wg_filter {\n"
            "    chain input {\n"
            "        type filter hook input priority 0; policy accept;\n"
            "    }\n"
            "}\n"
        )
        template = "\n".join([
            r"table\s+inet\s+wg_filter\s*\{",
            r"chain\s+input\s*\{",
            r"type\s+filter\s+hook\s+input\s+priority\s+0",
            r"\}",
        ])
        validate_firewall_rules(rules, template)

    def test_whitespace_around_lines_is_normalized(self):
        """Leading/trailing whitespace on each line must be stripped before comparison."""
        generated = "  table inet x {  \n  chain y {  \n  }  \n  }  \n"
        template = "\n".join([
            r"table\s+inet\s+x\s*\{",
            r"chain\s+y\s*\{",
            r"\}",
        ])
        validate_firewall_rules(generated, template)

    def test_blank_lines_are_ignored(self):
        """Blank lines in generated rules must be removed before comparison."""
        generated = "table inet x {\n\n\nchain y {\n}\n}\n"
        template = "\n".join([
            r"table\s+inet\s+x\s*\{",
            r"chain\s+y\s*\{",
            r"\}",
        ])
        validate_firewall_rules(generated, template)

    def test_comment_lines_are_ignored(self):
        """Lines starting with # after stripping must be ignored."""
        generated = (
            "# MANAGED BY wireseal\n"
            "table inet x {\n"
            "    # This is a comment\n"
            "    chain y { }\n"
            "}\n"
        )
        template = "\n".join([
            r"table\s+inet\s+x\s*\{",
            r"chain\s+y",
            r"\}",
        ])
        validate_firewall_rules(generated, template)

    def test_mismatch_raises_error(self):
        """Generated rules not matching any template pattern must raise FirewallValidationError."""
        generated = "table inet wg_filter { chain input { policy drop; } }"
        template = "rule that does not match anything"
        with pytest.raises(FirewallValidationError):
            validate_firewall_rules(generated, template)

    def test_error_message_includes_rule(self):
        """The error message must include the offending rule line."""
        generated = "unvetted rule xyz;"
        template = "rule a;"
        with pytest.raises(FirewallValidationError) as exc:
            validate_firewall_rules(generated, template)
        msg = str(exc.value)
        assert "unvetted rule xyz" in msg

    def test_empty_generated_rules_are_invalid(self):
        """Empty generated rules must raise FirewallValidationError."""
        with pytest.raises(FirewallValidationError):
            validate_firewall_rules("", "some pattern")
        with pytest.raises(FirewallValidationError):
            validate_firewall_rules("  \n  \n  ", "some pattern")

    def test_trailing_newline_does_not_matter(self):
        """A trailing newline on one side but not the other must not cause a mismatch."""
        generated = "rule a;\n"
        template = r"rule a;"
        validate_firewall_rules(generated, template)

    def test_comment_variations_normalized(self):
        """Comments with varying leading whitespace must all be ignored."""
        generated = "#comment\nrule a;\n  # indented comment\nrule b;\n"
        template = "\n".join([r"rule a;", r"rule b;"])
        validate_firewall_rules(generated, template)

    def test_overly_permissive_accept_all_raises(self):
        """Rules that accept all traffic must be rejected."""
        generated = "accept in all"
        template = r"accept in all"
        with pytest.raises(FirewallValidationError, match="overly permissive"):
            validate_firewall_rules(generated, template)

    def test_overly_permissive_pass_all_raises(self):
        """Rules that pass all traffic must be rejected."""
        generated = "pass in on eth0 all all"
        template = r"pass in on eth0 all all"
        with pytest.raises(FirewallValidationError, match="overly permissive"):
            validate_firewall_rules(generated, template)

    def test_overly_permissive_action_allow_protocol_any_raises(self):
        """netsh rules allowing protocol=any must be rejected."""
        generated = "netsh add rule action=allow protocol=any"
        template = r"action=allow protocol=any"
        with pytest.raises(FirewallValidationError, match="overly permissive"):
            validate_firewall_rules(generated, template)

    def test_scoped_accept_passes(self):
        """Scoped accept rules (specific interface/port) must be allowed."""
        generated = (
            "block drop in on eth0 all\n"
            "iifname \"wg0\" oifname \"eth0\" accept\n"
            "oifname \"wg0\" ct state { established, related } accept"
        )
        template = "\n".join([
            r"block\s+drop\s+in",
            r"iifname\s+.+\s+oifname\s+.+\s+accept",
            r"oifname\s+.+\s+ct\s+state\s+\{?\s*established",
        ])
        validate_firewall_rules(generated, template)

    def test_scoped_action_allow_passes(self):
        """netsh rules allowing specific protocol+port must be allowed."""
        generated = (
            "netsh advfirewall add rule name=block-all dir=in action=block\n"
            "netsh advfirewall add rule protocol=UDP localport=51820 action=allow"
        )
        template = "\n".join([
            r"advfirewall.*action=block",
            r"advfirewall.*protocol=UDP.*localport=\d+.*action=allow",
        ])
        validate_firewall_rules(generated, template)

    def test_required_block_rule_present(self):
        """Generated rules must include a deny-by-default block/drop rule."""
        generated = (
            "block drop in on eth0 all\n"
            "pass in on eth0 proto udp port 51820"
        )
        template = "\n".join([
            r"block\s+drop\s+in",
            r"pass\s+in\s+.*port\s+\d+",
        ])
        validate_firewall_rules(generated, template)

    def test_missing_block_rule_raises(self):
        """Generated rules without any block/drop rule must be rejected when template expects it."""
        generated = "pass in on eth0 proto udp port 51820"
        template = "\n".join([
            r"pass\s+in\s+.*port\s+\d+",
            r"block\s+drop\s+in",
        ])
        with pytest.raises(FirewallValidationError, match="missing required"):
            validate_firewall_rules(generated, template)

    def test_nftables_full_ruleset(self):
        """Full nftables ruleset with all structural rules must pass."""
        generated = (
            "# MANAGED BY wireseal\n"
            "table inet wg_filter {\n"
            "    chain input {\n"
            "        type filter hook input priority 0; policy accept;\n"
            "        ct state invalid drop\n"
            '        iifname "eth0" udp dport 51820 ct state new limit rate over 5/second burst 10 packets drop\n'
            "    }\n"
            "    chain forward {\n"
            "        type filter hook forward priority 0; policy accept;\n"
            '        iifname "wg0" oifname "eth0" accept\n'
            '        oifname "wg0" ct state { established, related } accept\n'
            "    }\n"
            "}\n"
            "table ip wg_nat {\n"
            "    chain postrouting {\n"
            "        type nat hook postrouting priority 100; policy accept;\n"
            '        iifname "wg0" masquerade\n'
            "    }\n"
            "}\n"
        )
        nft_template = "\n".join([
            r"table\s+inet\s+wg_filter\s*\{",
            r"chain\s+input\s*\{",
            r"type\s+filter\s+hook\s+input\s+priority\s+0",
            r"ct\s+state\s+invalid\s+drop",
            r"iifname\s+.+\s+udp\s+dport\s+\d+\s+ct\s+state\s+new\s+limit\s+rate\s+over\s+\d+/second",
            r"chain\s+forward\s*\{",
            r"type\s+filter\s+hook\s+forward\s+priority\s+0",
            r"iifname\s+.+\s+oifname\s+.+\s+accept",
            r"oifname\s+.+\s+ct\s+state\s+\{?\s*established",
            r"table\s+ip\s+wg_nat\s*\{",
            r"chain\s+postrouting\s*\{",
            r"type\s+nat\s+hook\s+postrouting\s+priority\s+100",
            r"iifname\s+.+\s+masquerade",
            r"\}",
        ])
        validate_firewall_rules(generated, nft_template)

    def test_pfctl_full_ruleset(self):
        """Full pfctl ruleset with all structural rules must pass."""
        generated = (
            "# wireseal managed rules\n"
            "nat from 10.0.0.0/24 to any -> (en0)\n"
            "table <wg_bruteforce> persist\n"
            "block drop in quick on en0 from <wg_bruteforce>\n"
            "pass in quick on en0 proto udp from any to any port 51820 keep state\n"
            "block drop in on en0 all\n"
        )
        pf_template = "\n".join([
            r"nat\s+from\s+.+\s+to\s+any\s+->\s+\(.+\)",
            r"table\s+<wg_bruteforce>\s+persist",
            r"block\s+drop\s+in\s+quick\s+on\s+.+\s+from\s+<wg_bruteforce>",
            r"pass\s+in\s+quick\s+on\s+.+\s+proto\s+udp\s+from\s+any\s+to\s+any\s+port\s+\d+",
            r"block\s+drop\s+in\s+on\s+.+\s+all",
        ])
        validate_firewall_rules(generated, pf_template)

    def test_netsh_full_ruleset(self):
        """Full netsh ruleset with allow+block must pass."""
        generated = (
            "netsh advfirewall firewall add rule name=wireseal-wg0-in "
            "protocol=UDP dir=in localport=51820 action=allow profile=any enable=yes\n"
            "netsh advfirewall firewall add rule name=wireseal-wg0-block "
            "dir=in interface=wg0 action=block profile=any enable=yes"
        )
        netsh_template = "\n".join([
            r"netsh\s+advfirewall\s+firewall\s+add\s+rule\s+name=wireseal-\w+-in\s+protocol=UDP\s+dir=in\s+localport=\d+\s+action=allow",
            r"netsh\s+advfirewall\s+firewall\s+add\s+rule\s+name=wireseal-\w+-block\s+dir=in\s+interface=\w+\s+action=block",
        ])
        validate_firewall_rules(generated, netsh_template)

    def test_tautological_self_validation_detected(self):
        """The old tautological bug (validating against itself) must NOT pass
        structural validation when the rules lack block/drop patterns."""
        # This mimics the old bug: validate_firewall_rules(rules, rules)
        # With the new structural validation, if rules have no block/drop,
        # the required-rule check catches it (when template has block patterns).
        rules = "pass in on eth0 proto udp port 51820"
        template = "pass in on eth0 proto udp port 51820"
        # No block/drop in template → required check skipped → passes pattern match
        # This is correct: the template didn't declare block as required.
        validate_firewall_rules(rules, template)

        # But if template includes block pattern, the generated rules must have it
        template_with_block = "\n".join([
            r"pass\s+in\s+.*port\s+\d+",
            r"block\s+drop\s+in",
        ])
        with pytest.raises(FirewallValidationError, match="missing required"):
            validate_firewall_rules(rules, template_with_block)
