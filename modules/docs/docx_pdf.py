"""
Documents and Thai Typography Automation Module.
"""

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import load_config
from ..logger import logger


def get_libreoffice_path() -> Path:
    cfg = load_config()
    lo = cfg.get("libreoffice_path")
    if lo and os.path.exists(lo):
        return Path(lo)

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
    try:
        from ..security.confine import confine
        source_path = confine(input_file, kind="file")
        if output_directory:
            out_dir = confine(output_directory, kind="workspace", allow_create=True)
        else:
            out_dir = source_path.parent
    except FileNotFoundError as e:
        return {
            "success": False,
            "error": f"Input file '{input_file}' does not exist: {e}",
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Invalid or unconfined document conversion path: {e}",
        }

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
        logger.error(f"Error converting {input_file} to PDF: {e}")
        return {"success": False, "error": str(e)}
