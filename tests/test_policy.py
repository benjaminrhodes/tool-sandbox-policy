"""Tests for tool-sandbox-policy."""

import tempfile
from pathlib import Path


from src.policy import Policy, PolicyEngine, PolicyViolation


class TestPolicy:
    """Tests for Policy class."""

    def test_policy_creation_with_defaults(self):
        """Policy created with empty defaults."""
        policy = Policy()
        assert policy.allowed_file_paths == []
        assert policy.allowed_domains == []
        assert policy.name == "default"

    def test_policy_creation_with_custom_values(self):
        """Policy with custom allowed paths and domains."""
        policy = Policy(
            name="test_policy",
            allowed_file_paths=["/home/user/*", "/tmp/**"],
            allowed_domains=["example.com", "*.google.com"],
        )
        assert policy.name == "test_policy"
        assert policy.allowed_file_paths == ["/home/user/*", "/tmp/**"]
        assert policy.allowed_domains == ["example.com", "*.google.com"]

    def test_policy_to_dict(self):
        """Policy serializes to dict."""
        policy = Policy(
            name="test_policy",
            allowed_file_paths=["/home/user/*"],
            allowed_domains=["example.com"],
        )
        result = policy.to_dict()
        assert result["name"] == "test_policy"
        assert result["allowed_file_paths"] == ["/home/user/*"]
        assert result["allowed_domains"] == ["example.com"]

    def test_policy_from_dict(self):
        """Policy deserializes from dict."""
        data = {
            "name": "from_dict",
            "allowed_file_paths": ["/data/**"],
            "allowed_domains": ["api.test.com"],
        }
        policy = Policy.from_dict(data)
        assert policy.name == "from_dict"
        assert policy.allowed_file_paths == ["/data/**"]
        assert policy.allowed_domains == ["api.test.com"]

    def test_policy_save_load(self):
        """Policy saves and loads from JSON file."""
        policy = Policy(
            name="saved_policy",
            allowed_file_paths=["/home/*"],
            allowed_domains=["trusted.com"],
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = Path(f.name)
            policy.save(path)

        loaded = Policy.load(path)
        assert loaded.name == policy.name
        assert loaded.allowed_file_paths == policy.allowed_file_paths
        assert loaded.allowed_domains == policy.allowed_domains
        path.unlink()


class TestPolicyEngineFileAccess:
    """Tests for file access validation."""

    def test_allow_exact_path(self):
        """Exact file path is allowed."""
        policy = Policy(allowed_file_paths=["/home/user/file.txt"])
        engine = PolicyEngine(policy)
        result = engine.check_file_access("/home/user/file.txt")
        assert result.allowed is True

    def test_allow_glob_star(self):
        """Star glob allows anything under the path."""
        policy = Policy(allowed_file_paths=["/home/user/*"])
        engine = PolicyEngine(policy)
        assert engine.check_file_access("/home/user/file.txt").allowed is True
        assert engine.check_file_access("/home/user/subdir").allowed is True
        assert engine.check_file_access("/home/user/subdir/file.txt").allowed is True

    def test_allow_glob_double_star(self):
        """Double star allows recursive matching."""
        policy = Policy(allowed_file_paths=["/home/user/**"])
        engine = PolicyEngine(policy)
        assert engine.check_file_access("/home/user/file.txt").allowed is True
        assert engine.check_file_access("/home/user/subdir/file.txt").allowed is True
        assert engine.check_file_access("/home/other/file.txt").allowed is False

    def test_deny_path_not_in_policy(self):
        """Path not in policy is denied."""
        policy = Policy(allowed_file_paths=["/home/user/*"])
        engine = PolicyEngine(policy)
        result = engine.check_file_access("/etc/passwd")
        assert result.allowed is False
        assert "not allowed" in result.reason.lower()

    def test_empty_policy_denies_all(self):
        """Empty policy denies all file access."""
        policy = Policy(allowed_file_paths=[])
        engine = PolicyEngine(policy)
        result = engine.check_file_access("/any/path")
        assert result.allowed is False


class TestPolicyEngineNetworkAccess:
    """Tests for network access validation."""

    def test_allow_exact_domain(self):
        """Exact domain is allowed."""
        policy = Policy(allowed_domains=["example.com"])
        engine = PolicyEngine(policy)
        result = engine.check_network_access("example.com")
        assert result.allowed is True

    def test_allow_subdomain_wildcard(self):
        """Wildcard allows subdomains."""
        policy = Policy(allowed_domains=["*.google.com"])
        engine = PolicyEngine(policy)
        assert engine.check_network_access("google.com").allowed is True
        assert engine.check_network_access("www.google.com").allowed is True
        assert engine.check_network_access("api.google.com").allowed is True
        assert engine.check_network_access("google.com.evil.com").allowed is False

    def test_allow_port_in_domain(self):
        """Domain with port is allowed when base domain matches."""
        policy = Policy(allowed_domains=["api.example.com"])
        engine = PolicyEngine(policy)
        assert engine.check_network_access("api.example.com:443").allowed is True
        assert engine.check_network_access("api.example.com:8080").allowed is True

    def test_deny_domain_not_in_policy(self):
        """Domain not in policy is denied."""
        policy = Policy(allowed_domains=["allowed.com"])
        engine = PolicyEngine(policy)
        result = engine.check_network_access("evil.com")
        assert result.allowed is False

    def test_empty_policy_denies_all_network(self):
        """Empty policy denies all network access."""
        policy = Policy(allowed_domains=[])
        engine = PolicyEngine(policy)
        result = engine.check_network_access("any.com")
        assert result.allowed is False


class TestPolicyViolation:
    """Tests for PolicyViolation class."""

    def test_violation_creation(self):
        """Violation stores access details."""
        violation = PolicyViolation(
            allowed=False,
            resource_type="file",
            resource_path="/etc/passwd",
            reason="Path not in allowed list",
        )
        assert violation.allowed is False
        assert violation.resource_type == "file"
        assert violation.resource_path == "/etc/passwd"

    def test_violation_to_dict(self):
        """Violation serializes to dict."""
        violation = PolicyViolation(
            allowed=False,
            resource_type="network",
            resource_path="evil.com",
            reason="Domain not allowed",
        )
        result = violation.to_dict()
        assert result["allowed"] is False
        assert result["resource_type"] == "network"


class TestPolicyEngineIntegration:
    """Integration tests for PolicyEngine."""

    def test_combined_file_and_network_policy(self):
        """Engine handles both file and network policies."""
        policy = Policy(
            allowed_file_paths=["/data/**"],
            allowed_domains=["api.example.com", "*.trusted.io"],
        )
        engine = PolicyEngine(policy)

        assert engine.check_file_access("/data/file.txt").allowed is True
        assert engine.check_file_access("/other/file.txt").allowed is False
        assert engine.check_network_access("api.example.com").allowed is True
        assert engine.check_network_access("app.trusted.io").allowed is True
        assert engine.check_network_access("evil.com").allowed is False

    def test_strict_mode_blocks_all_by_default(self):
        """Strict mode blocks everything not explicitly allowed."""
        policy = Policy(
            allowed_file_paths=["/allowed/*"],
            allowed_domains=["allowed.com"],
            strict=True,
        )
        engine = PolicyEngine(policy)

        assert engine.check_file_access("/allowed/file.txt").allowed is True
        assert engine.check_file_access("/unknown/path").allowed is False
        assert engine.check_network_access("allowed.com").allowed is True
        assert engine.check_network_access("unknown.com").allowed is False
