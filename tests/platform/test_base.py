"""Tests for the platform adapter base module.

Verifies:
  - validate_firewall_rules function (FW-03)
  - Normalization logic (stripping, blank lines, comments)
  - FirewallValidationError on mismatch
  - Equality passes for identical rules
"""

import pytest

from wireseal.platform.base import validate_firewall_rules
from wireseal.platform.exceptions import FirewallValidationError


class TestValidateFirewallRules:
    """Module-level validate_firewall_rules function (FW-03)."""

    def test_identical_rules_pass(self):
        """Two identical rule strings must pass without error."""
        rules = (
            "table inet wg_filter {\n"
            "    chain input {\n"
            "        type filter hook input priority 0; policy accept;\n"
            "    }\n"
            "}\n"
        )
        validate_firewall_rules(rules, rules)

    def test_whitespace_around_lines_is_normalized(self):
        """Leading/trailing whitespace on each line must be stripped before comparison."""
        generated = "  table inet x {  \n  chain y {  \n  }  \n  }  \n"
        template = "table inet x {\nchain y {\n}\n}\n"
        validate_firewall_rules(generated, template)

    def test_blank_lines_are_ignored(self):
        """Blank lines in either string must be removed before comparison."""
        generated = "table inet x {\n\n\nchain y {\n}\n}\n"
        template = "table inet x {\nchain y {\n}\n}\n"
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
        template = "table inet x {\nchain y { }\n}\n"
        validate_firewall_rules(generated, template)

    def test_mismatch_raises_error(self):
        """Two different rule sets must raise FirewallValidationError."""
        generated = "table inet wg_filter { chain input { policy drop; } }"
        template = "table inet wg_filter { chain input { policy accept; } }"
        with pytest.raises(FirewallValidationError):
            validate_firewall_rules(generated, template)

    def test_error_message_includes_both_sides(self):
        """The error message must contain both expected and got values."""
        generated = "rule a;"
        template = "rule b;"
        with pytest.raises(FirewallValidationError) as exc:
            validate_firewall_rules(generated, template)
        msg = str(exc.value)
        assert "Expected" in msg
        assert "Got" in msg

    def test_empty_strings_are_valid(self):
        """Two empty or whitespace-only strings must pass."""
        validate_firewall_rules("", "")
        validate_firewall_rules("  \n  \n  ", "")

    def test_trailing_newline_does_not_matter(self):
        """A trailing newline on one side but not the other must not cause a mismatch."""
        generated = "rule a;\n"
        template = "rule a;"
        validate_firewall_rules(generated, template)

    def test_comment_variations_normalized(self):
        """Comments with varying leading whitespace must all be ignored."""
        generated = "#comment\nrule a;\n  # indented comment\nrule b;\n"
        template = "rule a;\nrule b;\n"
        validate_firewall_rules(generated, template)
