# Changelog

All notable changes to Protocol Brain will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-10-09

### Added
- **Security Policy & Capability-Based Execution:** Scoped OS execution into `git_read`, `git_write`, `run_tests`, `package_install`, and `system_control`.
- **Tool Classification:** Classified all tools into `SAFE`, `MUTATING`, and `DANGEROUS`.
- **Security Regression Test Suite:** 19 automated tests targeting command injection, metacharacters, operator chaining, CWD escapes, dangerous flags, and process protection.
- **Real MCP Protocol Integration Suite:** Added `tests/test_mcp_integration.py` performing full JSON-RPC stdio round-trips via `mcp.client`.
- **Hierarchical Configuration Precedence:** CLI overrides > Environment variables (`PROTOCOL_BRAIN_*`) > `config.local.json` > `config.json`.
- **Transport Security:** Block unauthenticated binding to non-loopback addresses (`0.0.0.0`) on HTTP/SSE.
- **Observability & Metrics:** Structured JSON event logging with secret redaction and runtime metrics tracking (`get_system_metrics`, `get_security_policy`).
- **Standard Project Files:** Added `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`.

### Changed
- Hardened `shell_runner.py` with `shell=False`, argument vector parsing, and recursive child process tree termination on timeout.
- Hardened `port_killer.py` with ancestor PID protection, critical process denylist, user-space port restriction (`1024-65535`), and post-kill verification.
- Completely eliminated hardcoded machine paths from `config.json` and `README.md`.

## [0.2.0] - 2026-10-09

### Added
- Expanded MCP toolset to 22 tools.
- `read_single_symbol`: Targeted function/class extraction saving up to 98.9% tokens.
- `find_code_references`: Contextual grep filtering out dependency directories.
- `check_git_status` and `get_git_diff`: Concise git summaries.
- `get_note_backlinks`: Graph backlink discovery across the Obsidian vault.
- `append_to_note` and `update_frontmatter`: Non-destructive note mutations.
- Measured empirical benchmark table across 8 modules (average 91.0% token reduction).

## [0.1.0] - 2026-10-09

### Added
- Initial release of Protocol Brain MCP Server.
- Basic Obsidian vault reader and wikilink resolver.
- Initial system port killer and LibreOffice Thai PDF converter.
