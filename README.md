# Tool Sandbox Policy Engine

Enforce file/network access policies for agent tools.

## Features

- Define sandbox policies with allowed file paths and network domains
- Validate tool access requests against policies
- Support for glob patterns (`*` and `**`)
- Wildcard domain matching (`*.example.com`)
- CLI for policy management

## Installation

```bash
pip install tool-sandbox-policy
```

## Usage

### Create a Policy

```bash
python -m src.cli init policy.json \
  --name my_policy \
  --allowed-paths /home/user/* /data/** \
  --allowed-domains example.com *.trusted.io
```

### Check Access

```bash
# Check file access
python -m src.cli check policy.json file /home/user/file.txt
# Output: ALLOWED: /home/user/file.txt

# Check network access
python -m src.cli check policy.json network api.example.com
# Output: ALLOWED: api.example.com
```

### Validate a Policy

```bash
python -m src.cli validate policy.json
```

### List Policy Contents

```bash
python -m src.cli list policy.json
```

## Policy File Format

```json
{
  "name": "my_policy",
  "allowed_file_paths": ["/home/*", "/data/**"],
  "allowed_domains": ["example.com", "*.trusted.io"],
  "strict": false
}
```

## Glob Patterns

- `*` - Matches any characters (including `/`) after the prefix
- `**` - Matches recursively (must be at end of pattern)

## Testing

```bash
pytest tests/ -v
```

## License

MIT
