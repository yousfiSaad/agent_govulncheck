# Govulncheck Agent for OXO

An OXO agent that wraps [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) to provide smart Go vulnerability scanning with reduced false positives.

## Overview

This agent analyzes Go source code to determine if vulnerable code is actually used, significantly reducing false positives compared to the OSV agent.

### Key Features

- **Smart Analysis**: Only reports vulnerabilities that are actually reachable in your code
- **Reduced False Positives**: Uses static analysis to check if vulnerable functions are called
- **Go-Specific**: Leverages the official Go vulnerability database
- **Docker-Based**: Runs govulncheck in a containerized environment

### Why This Matters

**Current OSV Agent:**
- Reports all vulnerabilities in dependencies
- Doesn't check if vulnerable code is actually used
- Higher false positive rate

**Govulncheck Agent:**
- Analyzes source code to see what's actually used
- Reports only relevant vulnerabilities
- Lower false positive rate
- Go-specific accuracy

## Getting Started

### Prerequisites

- Docker installed and running
- Python 3.11+ installed (for local development)
- Go 1.22+ installed (for testing)
- OXO CLI tool

### Installation

```bash
# Clone the repository
git clone <repository_url>
cd oxo_agent_govulncheck

# Build the Docker image
docker build -t govulncheck-agent:latest .

# Or build with OXO
uvx --from "git+https://github.com/yousfiSaad/oxo.git@fix/add-aarch64-architecture-support" \
  ostorlab agent build --file oxo.yaml --organization local
```

### Docker Image Details

- **Base Image**: Python 3.11 Alpine
- **Go Version**: 1.22.12
- **govulncheck Version**: v1.1.4
- **Image Size**: ~687MB (includes Go toolchain for source analysis)
- **Architecture**: Supports aarch64/arm64

### Usage

```bash
# Scan a Go module using go.mod file
uvx --from "git+https://github.com/yousfiSaad/oxo.git@fix/add-aarch64-architecture-support" \
  ostorlab scan run \
  --agent agent/local/govulncheck \
  --title "my-go-project-scan" \
  file --file /path/to/go.mod

# Or scan using go.sum file
uvx --from "git+https://github.com/yousfiSaad/oxo.git@fix/add-aarch64-architecture-support" \
  ostorlab scan run \
  --agent agent/local/govulncheck \
  --title "my-go-project-scan" \
  file --file /path/to/go.sum
```

### Example Scan Output

The agent will:
1. Receive the go.mod/go.sum file path
2. Extract the module directory
3. Run govulncheck with JSON output
4. Analyze call stacks to determine if vulnerabilities are reachable
5. Emit vulnerability reports with the `is_used` flag

Example vulnerability report:
```json
{
  "vulnerability_id": "GO-2025-3750",
  "title": "Vulnerability in crypto/x509",
  "description": "Detailed description...",
  "severity": "HIGH",
  "cvss_score": 7.5,
  "affected_package": "stdlib",
  "affected_version": "v1.22.12",
  "is_used": true,
  "recommendation": "Update to v1.23.10 or later",
  "references": ["https://pkg.go.dev/vuln/GO-2025-3750"]
}
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install -r tests/test-requirements.txt

# Run tests
pytest tests/
```

### Linting

```bash
ruff format .
ruff check .
```

### Static Type Checking

```bash
pip install -r typing-requirements.txt
mypy
```

## Project Structure

```
govulncheck-agent/
├── Dockerfile                    # Agent container definition
├── agent/
│   ├── __init__.py
│   ├── __main__.py              # Entry point
│   ├── agent.py                 # Main agent logic
│   └── govulncheck_wrapper.py   # govulncheck execution wrapper
├── tests/
│   ├── __init__.py
│   ├── test_agent.py
│   └── fixtures/
│       └── sample_govulncheck.json
├── requirements.txt              # Python dependencies
├── oxo.yaml                      # Agent definition
└── README.md                     # This file
```

## How It Works

1. **Receives File Assets**: The agent listens for `go.mod` and `go.sum` files as entry points
2. **Locates Module Directory**: Extracts the module root directory from the file path
3. **Scans Entire Module**: Runs `govulncheck ./...` from the module directory to analyze all Go source code
4. **Analyzes Results**: Converts govulncheck output to OXO vulnerability format
5. **Reports Vulnerabilities**: Emits vulnerability reports with `is_used` flag indicating if vulnerable code is actually called

**Note**: While the agent receives only `go.mod`/`go.sum` file paths, it scans the entire Go module directory (all `.go` files) to determine if vulnerable functions are actually used in the codebase. This is why it's more accurate than dependency-only scanners.

## Configuration

The agent is configured via `oxo.yaml`:

```yaml
kind: Agent
name: govulncheck
version: 0.1.0
in_selectors:
  - v3.asset.file[path=**/go.mod]
  - v3.asset.file[path=**/go.sum]
out_selectors:
  - v3.report.vulnerability
```

## Contributing

To contribute to this project:

1. Fork this repository
2. Clone your forked repository
3. Create a new branch: `git checkout -b <branch_name>`
4. Install dependencies: `pip install -r requirements.txt`
5. Make your changes
6. Run tests: `pytest tests/`
7. Run linter: `ruff check .`
8. Commit your changes: `git commit -m '<commit_message>'`
9. Push to your branch: `git push origin <branch_name>`
10. Create a pull request

## References

- [Ostorlab Template Agent](https://github.com/Ostorlab/template_agent)
- [govulncheck Documentation](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [OXO Agent Development Guide](https://docs.ostorlab.co/)
- [Go Vulnerability Database](https://vuln.go.dev/)

## License

See LICENSE file for details.
