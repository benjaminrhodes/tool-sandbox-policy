"""Tests for CLI."""

import json

import pytest

from src.cli import main


class TestCLI:
    """Tests for CLI commands."""

    def test_main_help(self, capsys):
        """CLI shows help."""
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "tool-sandbox-policy" in captured.out.lower()

    def test_init_creates_policy_file(self, tmp_path):
        """init command creates a policy file."""
        policy_file = tmp_path / "policy.json"
        result = main(["init", str(policy_file)])
        assert result == 0
        assert policy_file.exists()
        data = json.loads(policy_file.read_text())
        assert data["name"] == "default"

    def test_init_with_options(self, tmp_path):
        """init with custom options."""
        policy_file = tmp_path / "policy.json"
        result = main(
            [
                "init",
                str(policy_file),
                "--name",
                "custom",
                "--allowed-paths",
                "/home/*",
                "/data/**",
                "--allowed-domains",
                "example.com",
                "*.trusted.io",
            ]
        )
        assert result == 0
        data = json.loads(policy_file.read_text())
        assert data["name"] == "custom"
        assert data["allowed_file_paths"] == ["/home/*", "/data/**"]
        assert data["allowed_domains"] == ["example.com", "*.trusted.io"]

    def test_check_file_allowed(self, tmp_path):
        """check file access - allowed."""
        policy_file = tmp_path / "policy.json"
        Policy = __import__("src.policy", fromlist=["Policy"]).Policy
        policy = Policy(allowed_file_paths=["/home/*"])
        policy.save(policy_file)

        result = main(["check", str(policy_file), "file", "/home/user/file.txt"])
        assert result == 0

    def test_check_file_denied(self, tmp_path):
        """check file access - denied."""
        policy_file = tmp_path / "policy.json"
        Policy = __import__("src.policy", fromlist=["Policy"]).Policy
        policy = Policy(allowed_file_paths=["/home/*"])
        policy.save(policy_file)

        result = main(["check", str(policy_file), "file", "/etc/passwd"])
        assert result == 1

    def test_check_network_allowed(self, tmp_path):
        """check network access - allowed."""
        policy_file = tmp_path / "policy.json"
        Policy = __import__("src.policy", fromlist=["Policy"]).Policy
        policy = Policy(allowed_domains=["example.com"])
        policy.save(policy_file)

        result = main(["check", str(policy_file), "network", "example.com"])
        assert result == 0

    def test_check_network_denied(self, tmp_path):
        """check network access - denied."""
        policy_file = tmp_path / "policy.json"
        Policy = __import__("src.policy", fromlist=["Policy"]).Policy
        policy = Policy(allowed_domains=["example.com"])
        policy.save(policy_file)

        result = main(["check", str(policy_file), "network", "evil.com"])
        assert result == 1

    def test_validate_valid_policy(self, tmp_path):
        """validate command with valid policy."""
        policy_file = tmp_path / "policy.json"
        Policy = __import__("src.policy", fromlist=["Policy"]).Policy
        policy = Policy(allowed_file_paths=["/home/*"])
        policy.save(policy_file)

        result = main(["validate", str(policy_file)])
        assert result == 0

    def test_validate_invalid_policy(self, tmp_path):
        """validate command with invalid policy."""
        policy_file = tmp_path / "policy.json"
        policy_file.write_text('{"name": 123}')

        result = main(["validate", str(policy_file)])
        assert result == 1

    def test_list_shows_policy(self, tmp_path, capsys):
        """list command shows policy contents."""
        policy_file = tmp_path / "policy.json"
        Policy = __import__("src.policy", fromlist=["Policy"]).Policy
        policy = Policy(
            name="test",
            allowed_file_paths=["/home/*"],
            allowed_domains=["example.com"],
        )
        policy.save(policy_file)

        result = main(["list", str(policy_file)])
        assert result == 0
        captured = capsys.readouterr()
        assert "test" in captured.out
        assert "/home/*" in captured.out
        assert "example.com" in captured.out
