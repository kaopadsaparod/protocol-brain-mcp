# Changelog

All notable changes to Protocol Brain will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-09

### Added
- **Fast Context Engine & Terminal AI Intelligence Suite (Expanded to 32 Tools):**
  - `prepare_context`: Synthesizes minimal, high-signal context packets with AST symbol slices under strict hard token budgets, delivering ~90% token savings and sub-100ms response times.
  - `inspect_project`: Instant architectural blueprints detecting tech stacks, package managers, entry points, test runners, and directory trees without running LLM inference.
  - `trace_error`: Multi-language stack trace parser (Python tracebacks, Node/TypeScript stack traces, Go panics) locating crash sites in workspace source code, slicing crash definitions, and extracting callers and test targets.
  - `find_impact`: Blast radius calculation before refactoring, mapping symbol usages, dependent modules, affected tests, and assessing change risk (LOW/MEDIUM/HIGH/CRITICAL).
  - `find_relevant_tests`: Pinpoints tests covering target files or symbols and generates tailored test commands (e.g. `pytest <file> -k <test>`).
  - `git_context`: Token-compact Git history, recent authors, and co-changed files (files frequently modified together).
  - `inspect_runtime`: Snapshot of development OS, Python/Node/Git/Docker versions, virtual environment detection, and 100% secret redaction (protecting tokens, keys, passwords).
  - `inspect_local_services`: Fast local port scanning identifying dev servers (Vite, Next, FastAPI, Express) and databases (Postgres, Redis, Mongo).
- **Persistent SQLite Relational Index (`.protocol_brain/index.db`):**
  - Fast relational schema with WAL mode tracking files, AST symbols, imports, symbol references, tests, and git metadata.
- **3-Tier Multi-Level Cache:**
  - L1 Request-scoped context cache.
  - L2 Thread-safe memory LRU cache with TTL.
  - L3 SQLite persistent index with `mtime` + `size` fast-path skipping (< 1ms per unchanged file).
- **Hard Token Budget Enforcement:**
  - `TokenBudgetSlicePacker` guarantees returned tokens never exceed the user-specified budget ceiling.
- **Automated Test Suite Expansion:**
  - Expanded test coverage from 52 to 72 passing automated tests across 12 test suites.

## [0.2.1] - 2026-10-09

### Added
- **HTTP / SSE Request-Time Bearer Authentication:** Built `BearerAuthMiddleware` on Starlette ASGI app enforcing `Authorization: Bearer <token>` on `/mcp`, `/sse` with `401 Unauthorized` for invalid or missing credentials.
- **Universal Tool Observability & Thread-Safe Metrics:** Wired `@observe_tool` decorator across all 24 tools, updating `MetricsRegistry` protected by `threading.RLock()` and recording latency, success rate, error categorization, and token savings.
- **Narrowed Execution Roots (`trusted_workspaces`):** Restricted shell execution `cwd` exclusively to vetted workspaces (repo root, `D:\vault`) to eliminate untrusted repo `conftest.py` execution risks.
- **Binary PATH Hijacking Defense:** Hardened `resolve_executable` to block binaries in unvetted directories (`Downloads`, `Temp`, CWD) and restrict execution to verified system and runtime directories.
- **Process Killer TOCTOU Defense:** Guarded `free_port` against Windows PID recycling races by verifying `create_time` before process termination.
- **Real Timeout Subprocess Fixture:** Added `tests/fixtures/sleep_process.py` and regression tests verifying real timeout and recursive process-tree termination.
- **5-Tier Tool Security Taxonomy:** Expanded classification to `READ_ONLY`, `USER_VISIBLE`, `DATA_MUTATION`, `PROCESS_EXECUTION`, and `PROCESS_TERMINATION`.
- **GitHub Actions Windows CI Matrix:** Added `.github/workflows/ci.yml` testing across Python 3.11, 3.12, and 3.13 on `windows-latest`.
- **Security Regression Suite Expansion:** Expanded automated test suite from 41 to 52 passing tests covering unit, regression, HTTP auth, thread safety, and MCP protocol integration.

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
