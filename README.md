# 🧠 Protocol Brain (`protocol-brain`)

> **Universal Model Context Protocol (MCP) Server**  
> Gateway อเนกประสงค์สำหรับ AI Agents (**Antigravity / agy**, **Claude Code**, **Aider**, **Ollama**)  
> ผสาน **Obsidian Second Brain**, **Code Intelligence (ลด Token วัดผลจริง 91.0%)**, และ **Windows OS & Git Power Tools**

[![CI](https://github.com/kaopadsaparod/protocol-brain-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/kaopadsaparod/protocol-brain-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![MCP: 2.3.0](https://img.shields.io/badge/mcp-2.3.0-green.svg)](https://modelcontextprotocol.io/)

---

## 📌 สถาปัตยกรรมระบบ (Architecture Overview)

```mermaid
flowchart TD
    subgraph Clients["AI Clients"]
        AGY["Antigravity (agy CLI / VS Code)"]
        CLAUDE["Claude Code / Terminal AI"]
        LOCAL["Local AI (Ollama / Open WebUI)"]
    end

    subgraph MCP["Protocol Brain MCP Server (v0.2.0)"]
        Router["MCPServer (Official MCP SDK v2.3.0)"]
        Log["Safe Logger -> stderr / protocol_brain.log"]

        subgraph M1["1. Vault Memory & Graph"]
            T1["read_vault_index"]
            T2["get_note_by_wikilink"]
            T3["get_note_backlinks"]
            T4["list_projects"]
            T5["append_to_note / update_frontmatter"]
            T6["open_note_in_obsidian"]
        end

        subgraph M2["2. Code Intelligence & Token Saver"]
            T7["get_file_outline (AST)"]
            T8["read_single_symbol (ฟังก์ชันเฉพาะจุด)"]
            T9["find_code_references (Grep with Context)"]
            T10["truncate_build_errors"]
        end

        subgraph M3["3. Windows Guard & Git Power Tools"]
            T11["release_port (แก้ EADDRINUSE)"]
            T12["check_git_status / get_git_diff"]
            T13["run_windows_command (Hardened shell=False)"]
            T14["check_system_and_gpu (Auto VRAM detection)"]
            T15["convert_to_thai_pdf (LibreOffice)"]
        end
    end

    AGY -->|Stdio (Clean JSON-RPC)| Router
    CLAUDE -->|Stdio (Clean JSON-RPC)| Router
    LOCAL -->|SSE / HTTP| Router

    Router --> M1
    Router --> M2
    Router --> M3
```

---

## 📊 ตารางวัดผลจริง: การประหยัด Token (Empirical Benchmark)

> ทดสอบวัดผลจริงจาก 8 โมดูล Python ในโปรเจกต์ เปรียบเทียบระหว่าง:
> 1. **Full File:** โหลดโค้ดทั้งไฟล์เข้า Context Window
> 2. **File Outline:** ดึงเฉพาะแผนผังคลาส/ฟังก์ชันด้วย AST
> 3. **Single Symbol:** ดึงเฉพาะฟังก์ชันที่ต้องการแก้ไขจริงๆ

| ไฟล์ทดสอบ | จำนวนบรรทัด | โหลดทั้งไฟล์ (Tokens) | เรียกดู Outline (Tokens) | **% ลด Token (Outline)** | อ่านฟังก์ชันเดียว (Tokens) | **% ลด Token (Symbol)** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `server.py` | 332 | 2,949 | 738 | **-75.0%** | 32 | **-98.9%** |
| `reader.py` | 246 | 2,221 | 181 | **-91.9%** | 251 | **-88.7%** |
| `writer.py` | 219 | 1,963 | 164 | **-91.6%** | 136 | **-93.1%** |
| `outline.py` | 293 | 2,920 | 169 | **-94.2%** | 479 | **-83.6%** |
| `references.py` | 110 | 956 | 39 | **-95.9%** | - | - |
| `git_tools.py` | 171 | 1,344 | 107 | **-92.0%** | 27 | **-98.0%** |
| `shell_runner.py` | 153 | 1,340 | 109 | **-91.9%** | 109 | **-91.9%** |
| `port_killer.py` | 100 | 1,013 | 46 | **-95.5%** | 238 | **-76.5%** |
| **ค่าเฉลี่ยรวม** | - | **1,838** | **194** | **🔥 ลดลงเฉลี่ย 91.0%** | **181** | **🔥 ลดลงเฉลี่ย 90.1%** |

---

## 🛠️ รายการเครื่องมือทั้งหมด (22 MCP Tools)

### 1. Obsidian Second Brain & Graph
* `read_vault_index()`: อ่าน Master Index (`00_INDEX.md`) ทันที
* `get_note_by_wikilink(identifier)`: อ่านเนื้อหาโน้ตโดย resolve `[[WikiLinks]]` ข้ามโฟลเดอร์อัตโนมัติ (มีระบบป้องกัน Path Traversal)
* `get_note_backlinks(identifier)`: สำรวจ Backlinks ว่ามีโน้ตใดบ้างใน Vault ที่ลิงก์มายังโน้ตนี้
* `search_vault_notes(query, folder)`: ค้นหาคำในโน้ต Markdown
* `list_projects()`: แสดงรายชื่อโปรเจกต์ทั้งหมดที่มีในโฟลเดอร์ `02_Projects/` พร้อมชื่อ Title
* `append_to_note(identifier, content, heading)`: ต่อเติมเนื้อหาเข้าท้ายโน้ตหรือใต้หัวข้อที่กำหนด (ไม่เขียนทับ)
* `update_frontmatter(identifier, metadata_updates)`: อัปเดต/เพิ่มค่าใน YAML Frontmatter โดยคงเนื้อหา Markdown เดิมไว้
* `log_project_progress(proj, summary)`: บันทึก Log งานความคืบหน้าเข้าโฟลเดอร์โปรเจกต์
* `create_new_note(path, title, content, tags)`: สร้างโน้ตใหม่ (ป้องกันการเขียนทับไฟล์เดิม)
* `open_note_in_obsidian(identifier)`: ยิงคำสั่ง URI สั่งให้แอป Obsidian บนหน้าจอเปิดหน้านั้นขึ้นมาทันที

### 2. Code Intelligence & Token Savers
* `get_file_outline(file_path)`: ดึงโครงสร้างคลาส/ฟังก์ชันผ่าน Python AST หรือ JS/TS parser
* `read_single_symbol(file_path, symbol_name)`: ดึงเฉพาะโค้ดของฟังก์ชันหรือคลาสนั้นๆ ออกมา
* `find_code_references(query, root_dir, context_lines)`: Grep โค้ดแบบมี Context บรรทัดบน-ล่าง กรองโฟลเดอร์ขยะออกอัตโนมัติ
* `truncate_build_errors(raw_log)`: ตัด Log บิวด์/เทสต์ยาวๆ เหลือเฉพาะจุด Error และ Stack Trace สำคัญ

### 3. Windows Guard & Git Power Tools
* `release_port(port)`: ค้นหา PID ที่ยึดพอร์ต dev (1024-65535) แล้ว Terminate Process Tree ทันที แก้ปัญหา `EADDRINUSE`
* `get_active_listening_ports()`: ดูรายการพอร์ต TCP ที่กำลังถูกใช้งาน
* `check_git_status(repo_path)`: ตรวจสถานะ Git (Branch, Staged, Unstaged, Untracked) ในรูปแบบกระชับ
* `get_git_diff(repo_path, staged_only)`: ดูสรุป Diff สถิติการแก้ไขไฟล์ พร้อมตัวอย่าง Diff แบบจำกัดบรรทัด
* `run_windows_command(cmd, cwd)`: รันคำสั่งปลอดภัย (`shell=False`, Argument vector, ป้องกัน Shell Injection, ปรับ `npm.cmd` อัตโนมัติ)
* `check_system_and_gpu()`: เช็คโหลด CPU, RAM, เนื้อที่ดิสก์ และตรวจจับ VRAM ของการ์ดจอ NVIDIA อัตโนมัติ
* `notify_user_windows(title, msg)`: ส่งการแจ้งเตือน Windows Toast Notification
* `convert_to_thai_pdf(input_file)`: แปลง DOCX/MD เป็น PDF ภาษาไทยด้วย LibreOffice Headless

---

## 🔒 การรักษาความปลอดภัยเชิงลึก (Security & Hardening)

> [!IMPORTANT]
> **คำแนะนำสำหรับ AI Client:** เพื่อความปลอดภัยสูงสุด แนะนำให้ตั้งค่า AI Client (เช่น `agy` หรือ Claude Code) ให้ **ถามยืนยันก่อนรันคำสั่ง (User Confirmation / Ask Permission)** สำหรับ 2 เครื่องมือนี้เสมอ:
> - `run_windows_command`
> - `release_port`
> **ห้ามเปิด auto-approve สำหรับคำสั่งที่มีผลต่อระบบปฏิบัติการ**

1. **Hardened Shell Runner (`shell_runner.py`):**
   - รันด้วย `shell=False` ส่งผ่านเป็น Argument Vector เสมอ ป้องกันการพ่วงคำสั่ง cmd.exe
   - ปฏิเสธ Metacharacters: `&`, `|`, `<`, `>`, `^`, `%`, `\n`, `\r`, `;`, `` ` ``
   - ตรวจจับและปฏิเสธ Flag อันตรายสำหรับการรันโค้ดสด เช่น `python -c`, `node -e`, `git -c`
   - ค้นหา Binary ตรงจาก System `PATH` เท่านั้น ไม่อนุญาตให้รัน binary ที่วางดักไว้ใน `cwd`
   - จำกัดไดเรกทอรีทำงานให้อยู่เฉพาะใน `allowed_roots`
   - เพดาน Timeout เข้มงวด หากเกินเวลาจะสั่งฆ่า Process Tree ลูกหลานทั้งหมดด้วย `psutil.children(recursive=True)`
   - จำกัดความยาว Output ตาม `max_log_lines` และเพดานไบต์
2. **Hardened Port Killer (`port_killer.py`):**
   - จำกัดพอร์ตเฉพาะ User-space `1024 - 65535` ไม่อนุญาตให้ยุ่งกับพอร์ตระบบ (0-1023)
   - ป้องกันไม่ให้ฆ่า Process ตัวเองและ Ancestors/Parent ทั้งหมด (เช่น ตัว client หรือ terminal host)
   - มี **Denylist** คุ้มครองโปรเซสสำคัญ: `code.exe`, `claude.exe`, `ollama.exe`, `docker.exe`, `postgres.exe`, `explorer.exe`, `svchost.exe`
   - ตรวจสอบความพร้อมซ้ำ (Post-verification) หลังการสั่งฆ่า เพื่อยืนยันว่าพอร์ตว่างจริง
3. **การส่ง Log ผ่าน `stderr` เท่านั้น:**
   - ช่องทาง `stdout` ถูกสงวนไว้ 100% สำหรับ MCP JSON-RPC Protocol สตรีมไม่มีการปนเปื้อนของ print
4. **Actionable Error Handling:**
   - คืนค่าโครงสร้าง `{ "success": false, "error": "...", "actionable_hint": "..." }` เพื่อให้ AI ไปต่อได้ถูกทาง
5. **Local Config Override:**
   - รองรับ `config.local.json` สำหรับการตั้งค่าเฉพาะเครื่องโดยไม่ถูก Commit ขึ้น Git

---

## 🔌 วิธีการเชื่อมต่อกับ AI

### 1. เชื่อมต่อกับ Antigravity (`agy` / VS Code Extension)
เพิ่มใน `~/.gemini/config/mcp_config.json`:
```json
{
  "mcpServers": {
    "protocol-brain": {
      "command": "python",
      "args": [
        "<ABSOLUTE_PATH_TO_REPO>\\server.py",
        "--transport",
        "stdio"
      ]
    }
  }
}
```
*(แทนที่ `<ABSOLUTE_PATH_TO_REPO>` ด้วยพาธที่โคลนโปรเจกต์ เช่น `C:\\Users\\<Username>\\Desktop\\protocol_brain`)*

### 2. เชื่อมต่อกับ Claude Code / Claude Desktop
เพิ่มใน `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "protocol-brain": {
      "command": "python",
      "args": [
        "<ABSOLUTE_PATH_TO_REPO>\\server.py",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

### 3. เชื่อมต่อกับ Local AI (Ollama + Open WebUI / AnythingLLM)
รันในโหมด SSE:
```powershell
python server.py --transport sse --port 8000
```
ตั้งค่าใน Open WebUI ที่ **Settings > Tools > MCP URL**: `http://localhost:8000/sse`

---

## 🧪 การทดสอบและควบคุมคุณภาพโค้ด (Tests & CI)

โปรเจกต์มาพร้อมชุดทดสอบ `pytest` ครอบคลุมทั้ง **Happy Path, Edge Cases, และ Security Failure Cases**:

```powershell
# รันชุดทดสอบ 22 เคส
python -m pytest -v

# ตรวจสอบ Code Quality และ Linting ด้วย ruff
python -m ruff check .
```

---

## 📄 License

MIT License - ดูรายละเอียดในไฟล์ [LICENSE](LICENSE)
