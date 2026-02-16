"""CLI interface."""

import argparse
import sys
from pathlib import Path

from src.policy import Policy, PolicyEngine


def cmd_init(args):
    """Initialize a new policy file."""
    policy = Policy(
        name=args.name,
        allowed_file_paths=args.allowed_paths or [],
        allowed_domains=args.allowed_domains or [],
    )
    policy.save(Path(args.output))
    print(f"Created policy file: {args.output}")
    return 0


def cmd_check(args):
    """Check if access is allowed."""
    policy = Policy.load(Path(args.policy))
    engine = PolicyEngine(policy)

    if args.resource_type == "file":
        result = engine.check_file_access(args.resource)
    elif args.resource_type == "network":
        result = engine.check_network_access(args.resource)
    else:
        print(f"Unknown resource type: {args.resource_type}", file=sys.stderr)
        return 1

    if result.allowed:
        print(f"ALLOWED: {args.resource}")
        return 0
    else:
        print(f"DENIED: {args.resource} - {result.reason}")
        return 1


def cmd_validate(args):
    """Validate a policy file."""
    try:
        policy = Policy.load(Path(args.policy))
        print(f"Valid policy: {policy.name}")
        print(f"  Allowed paths: {len(policy.allowed_file_paths)}")
        print(f"  Allowed domains: {len(policy.allowed_domains)}")
        return 0
    except Exception as e:
        print(f"Invalid policy: {e}", file=sys.stderr)
        return 1


def cmd_list(args):
    """List policy contents."""
    policy = Policy.load(Path(args.policy))
    print(f"Policy: {policy.name}")
    print("  Allowed file paths:")
    for p in policy.allowed_file_paths:
        print(f"    - {p}")
    if not policy.allowed_file_paths:
        print("    (none)")
    print("  Allowed domains:")
    for d in policy.allowed_domains:
        print(f"    - {d}")
    if not policy.allowed_domains:
        print("    (none)")
    return 0


def main(argv=None):
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="tool-sandbox-policy",
        description="Enforce file/network access policies for agent tools",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a new policy file")
    init_parser.add_argument("output", help="Output policy file path")
    init_parser.add_argument("--name", default="default", help="Policy name")
    init_parser.add_argument("--allowed-paths", nargs="+", help="Allowed file paths (globs)")
    init_parser.add_argument("--allowed-domains", nargs="+", help="Allowed network domains")
    init_parser.set_defaults(func=cmd_init)

    check_parser = subparsers.add_parser("check", help="Check if access is allowed")
    check_parser.add_argument("policy", help="Policy file path")
    check_parser.add_argument("resource_type", choices=["file", "network"], help="Resource type")
    check_parser.add_argument("resource", help="Resource to check")
    check_parser.set_defaults(func=cmd_check)

    validate_parser = subparsers.add_parser("validate", help="Validate a policy file")
    validate_parser.add_argument("policy", help="Policy file path")
    validate_parser.set_defaults(func=cmd_validate)

    list_parser = subparsers.add_parser("list", help="List policy contents")
    list_parser.add_argument("policy", help="Policy file path")
    list_parser.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
