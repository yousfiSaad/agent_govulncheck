# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-06

### Added
- Initial release of govulncheck agent for OXO
- Smart vulnerability detection with `is_used` flag based on static analysis
- Multi-stage Docker build for optimized image size
- Support for scanning go.mod and go.sum files
- Comprehensive unit tests with 4 test cases
- CI/CD pipelines for testing, linting, and type checking
- CVSS-based severity mapping (CRITICAL/HIGH/MEDIUM/LOW)
- Rich logging with colored output
- Timeout handling (5 minute scan timeout)
- Error handling and validation
- Go 1.22 toolchain integration for source code analysis

### Features
- Scans entire Go module directory to determine if vulnerable code is actually used
- Reduces false positives compared to OSV agent by analyzing call stacks
- Integrates with official Go vulnerability database
- Provides detailed vulnerability metadata including references
- Supports both go.mod and go.sum file entry points
- Module-level scanning with reachability analysis

### Technical Details
- Docker image size: ~687MB (includes Go toolchain for source analysis)
- Scan timeout: 5 minutes (configurable)
- Python 3.11 runtime with Alpine Linux base
- Go 1.22.12 for vulnerability analysis
- govulncheck v1.1.4

### Documentation
- Comprehensive README with usage examples
- Apache License 2.0
- Test fixtures and examples
- Contributing guidelines
- Integration testing with OXO framework

### Known Limitations
- Requires Go source code for accurate reachability analysis
- Larger image size due to Go toolchain requirement
- Scan time may be longer than simple dependency checkers due to static analysis

[0.1.0]: https://github.com/yourusername/oxo_agent_govulncheck/releases/tag/v0.1.0
