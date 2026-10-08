# 🤝 Contributing to Protocol Brain

Thank you for your interest in contributing to Protocol Brain!

## 🧪 Development Workflow

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/kaopadsaparod/protocol-brain-mcp.git
   cd protocol-brain-mcp
   ```

2. **Set up a virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. **Running the Test Suite:**
   All pull requests must pass the complete unit, security regression, and MCP protocol integration suites:
   ```powershell
   python -m pytest -v
   ```

4. **Linting and Formatting:**
   Code must adhere to Ruff linting standards:
   ```powershell
   python -m ruff check .
   ```

## 🔒 Security Requirements for New Tools

Every new tool must adhere to our [Security Policy](SECURITY.md):
* Categorize the tool explicitly as `SAFE`, `MUTATING`, or `DANGEROUS` in `modules/security/policy.py`.
* Never print to `stdout` in any tool module (use `modules/logger.py` to target `stderr` or log files).
* Ensure actionable error dictionaries are returned (`{"success": False, "error": "...", "actionable_hint": "..."}`).
* Add corresponding happy path and failure test cases to `tests/`.
