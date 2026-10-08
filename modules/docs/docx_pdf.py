import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

CONFIG_FILE = Path(__file__).resolve().parent.parent.parent / "config.json"


def get_libreoffice_path() -> Path:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                lo = cfg.get("libreoffice_path")
                if lo and os.path.exists(lo):
                    return Path(lo)
        except Exception:
            pass

    default_paths = [
        Path(r"C:\Program Files\LibreOffice\program\soffice.com"),
        Path(r"C:\Program Files\LibreOffice\program\soffice.exe"),
    ]
    for p in default_paths:
        if p.exists():
            return p
    return Path(r"C:\Program Files\LibreOffice\program\soffice.com")


def convert_document_to_pdf(
    input_file: str,
    output_directory: Optional[str] = None
) -> Dict[str, Any]:
    """
    Converts a DOCX or Markdown document to high-quality PDF using headless LibreOffice.
    Preserves Thai font rendering and vector graphics without float/drop accents.
    """
    source_path = Path(input_file)
    if not source_path.exists():
        return {
            "success": False,
            "error": f"Input file '{input_file}' does not exist.",
        }

    out_dir = Path(output_directory) if output_directory else source_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    soffice = get_libreoffice_path()
    if not soffice.exists():
        return {
            "success": False,
            "error": f"LibreOffice not found at {soffice}. Please install or check config.json.",
        }

    cmd = [
        str(soffice),
        "--headless",
        "--convert-to", "pdf",
        "--outdir", str(out_dir),
        str(source_path),
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        expected_pdf = out_dir / f"{source_path.stem}.pdf"

        if expected_pdf.exists():
            return {
                "success": True,
                "message": f"Successfully converted to {expected_pdf.name}",
                "pdf_path": str(expected_pdf),
            }
        else:
            return {
                "success": False,
                "error": f"Conversion completed with code {res.returncode} but PDF was not generated.",
                "stderr": res.stderr,
                "stdout": res.stdout,
            }
    except Exception as e:
        return {"success": False, "error": str(e)}
