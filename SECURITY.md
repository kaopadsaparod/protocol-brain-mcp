# 🛡️ Security Policy

## 🎯 Threat Model & Architecture

Protocol Brain bridges AI language models to local filesystem resources and operating system tools. Because language models are vulnerable to **prompt injection** (e.g., untrusted content within notes or scraped web pages instructing the AI to perform harmful system actions), Protocol Brain adopts a **zero-trust, defense-in-depth security model**:

```
                        ┌───────────────────────────────┐
                        │       AI / Agent Client       │
                        │   (UNTRUSTED PROMPT INPUT)    │
                        └───────────────┬───────────────┘
                                        │
                              MCP Protocol Boundary
                                        │
                ┌────────────────────────▼────────────────────────┐
                │              Protocol Brain v0.2.1              │
                │                                                 │
                │  [HTTP/SSE Bearer Auth]  [Observability Wrap]   │
                │  [Capability Policy]     [Sandbox Boundary]     │
                └───────────────┬─────────────────┬───────────────┘
                                │                 │
                 Trusted Reads  │                 │ Privileged Actions
            (READ_ROOTS: C, D, F)│                 │ (EXEC_ROOTS: trusted only)
                                ▼                 ▼
                        ┌───────────────┐ ┌───────────────┐
                        │ Obsidian Vault│ │ Hardened OS / │
                        │ AST Code Maps │ │ Git Sandboxes │
                        └───────────────┘ └───────────────┘
```

1. **Client Confirmation is NOT a Hard Boundary:** Client-side confirmation prompts can be manipulated by social engineering or automated agents. Therefore, the MCP server itself enforces strict, unbypassable execution policies.
2. **Capability-Based Execution:** OS commands are scoped by granular capabilities (`git_read`, `git_write`, `run_tests`, `package_install`, `system_control`).
3. **No Shell Interpreter:** Commands are parsed into discrete argument vectors and executed with `shell=False`.

---

## 🔒 Security Guarantees & Controls

### 1. OS Command Execution (`shell_runner.py`)
* **`shell=False` Strictly Enforced:** Commands never touch `cmd.exe` or `powershell.exe` for interpretation, blocking operator injection completely.
* **Metacharacter Rejection:** Any presence of `&`, `|`, `<`, `>`, `^`, `%`, `\n`, `\r`, `;`, or `` ` `` immediately rejects execution with an actionable error.
* **Dangerous Flag Inspection:** Flags that execute inline code (`python -c`, `node -e`, `node --eval`, `node -p`, `git -c`) are rejected before execution.
* **System PATH Resolution & Hijacking Defense:** Executables must resolve to genuine system binaries via approved system roots. Binaries placed in unvetted directories (`Downloads`, `Temp`, or directly inside `cwd`) are blocked.
* **Scoped Execution Workspaces (`trusted_workspaces`):** Working directories for command execution must reside within vetted workspaces (repository root and `D:\vault`), preventing malicious `conftest.py` execution from untrusted clones.
* **Process Tree Termination on Timeout:** When a command exceeds `safe_command_timeout_seconds`, all descendant child processes are recursively terminated using `psutil`.
* **Bounded Output:** Output is capped by `max_log_lines` and `max_output_bytes` to protect model context windows.

### 2. Process & Port Guard (`port_killer.py`)
* **User-Space Only:** Ports `< 1024` (system/privileged ports) are rejected.
* **Self & Ancestor Protection:** The server will never terminate its own PID or any parent/ancestor process (e.g. IDE client, terminal host).
* **Protected Process Denylist:** Critical services (`code.exe`, `claude.exe`, `ollama.exe`, `docker.exe`, `postgres.exe`, `explorer.exe`, `svchost.exe`) cannot be killed.
* **TOCTOU & PID Recycling Guard:** Captures process `create_time` and re-verifies before termination to prevent killing unrelated recycled PIDs.
* **Post-Kill Verification:** After attempting to release a port, the server inspects active connections to verify the port is genuinely free.

### 3. Filesystem & Vault Access (`reader.py`, `writer.py`)
* **Path Traversal Defense:** All note operations verify that the resolved canonical path remains strictly within the vault root.
* **Overwrite Protection:** `create_new_note` will refuse to overwrite existing files. Mutations must use explicit `append_to_note` or `update_frontmatter`.

### 4. Transport Security & Authentication
* **Request-Time Bearer Auth:** Starlette ASGI `BearerAuthMiddleware` enforces `Authorization: Bearer <token>` on HTTP and SSE endpoints, rejecting unauthorized requests with `401 Unauthorized`.
* **Loopback Safe Default:** SSE and Streamable HTTP transports bind to `127.0.0.1` by default.
* **Non-Loopback Blocking:** Binding to `0.0.0.0` or external network interfaces requires an explicit authentication token (`--auth-token` or `PROTOCOL_BRAIN_AUTH_TOKEN`).

---

## 📋 Tool Security Classification (5-Tier Taxonomy)

| Classification | Description | Tools |
| :--- | :--- | :--- |
| **`READ_ONLY`** | Non-mutating inspection of notes, AST, git, and system health | `read_vault_index`, `get_note_by_wikilink`, `search_vault_notes`, `list_projects`, `get_note_backlinks`, `get_file_outline`, `read_single_symbol`, `find_code_references`, `truncate_build_errors`, `get_active_listening_ports`, `check_system_and_gpu`, `check_git_status`, `get_git_diff`, `get_security_policy`, `get_system_metrics` |
| **`USER_VISIBLE`** | Dispatches UI notifications or opens app windows without data mutation | `notify_user_windows`, `open_note_in_obsidian` |
| **`DATA_MUTATION`** | Creates or modifies Markdown notes and generates documents | `append_to_note`, `update_frontmatter`, `log_project_progress`, `create_new_note`, `convert_to_thai_pdf` |
| **`PROCESS_EXECUTION`** | Runs scoped OS commands within vetted workspaces | `run_windows_command` |
| **`PROCESS_TERMINATION`** | Terminates processes holding network ports | `release_port` |

---

## 🚨 Reporting a Vulnerability

If you discover a security issue or bypass in Protocol Brain, please do not open a public issue. Instead, report it privately to the maintainer:
* **Maintainer:** Peeranat Boonplook (`kaopadsaparod`)
* **GitHub:** [https://github.com/kaopadsaparod/protocol-brain-mcp](https://github.com/kaopadsaparod/protocol-brain-mcp)
