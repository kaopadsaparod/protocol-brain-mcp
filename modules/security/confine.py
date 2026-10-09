"""
Path Confinement Engine for Protocol Brain.
Strictly validates paths against approved roots (trusted_workspaces or vault).
Rejects root drives, UNC paths, traversal, drive-relative paths, and escaping symlinks/junctions.
"""

import re
from pathlib import Path
from typing import List, Optional, Union

from ..vault.reader import get_vault_path
from .policy import get_trusted_workspaces, is_path_under_roots

_EXTRA_TRUSTED_WORKSPACES: List[Path] = []


def add_trusted_workspace(path: Union[str, Path]) -> None:
    """Dynamically register a trusted workspace root (e.g. for test fixtures)."""
    p = Path(path).resolve()
    if p not in _EXTRA_TRUSTED_WORKSPACES:
        _EXTRA_TRUSTED_WORKSPACES.append(p)


def remove_trusted_workspace(path: Union[str, Path]) -> None:
    """Remove a dynamically registered trusted workspace root."""
    p = Path(path).resolve()
    if p in _EXTRA_TRUSTED_WORKSPACES:
        _EXTRA_TRUSTED_WORKSPACES.remove(p)


def is_root_drive(path: Path) -> bool:
    """Detects if a path points directly to a filesystem root (e.g. 'C:\\' or '/')."""
    try:
        resolved = path.resolve()
        return resolved == Path(resolved.anchor).resolve()
    except Exception:
        return False


def is_unc_path(raw_str: str) -> bool:
    """Detects UNC paths like \\\\server\\share or //server/share."""
    s = raw_str.strip().replace("/", "\\")
    return s.startswith(r"\\") or s.startswith(r"\??\UNC") or s.startswith(r"\\?\UNC")


def is_drive_relative(raw_str: str) -> bool:
    """Detects drive-relative paths like 'C:foo.txt' or 'C:' on Windows."""
    s = raw_str.strip().strip("\"'")
    return bool(re.match(r"^[a-zA-Z]:($|[^\\/])", s))


DOS_DEVICE_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def is_dos_device_name(raw_str: str) -> bool:
    """Checks if any segment in the path uses Windows reserved device names (e.g. CON, NUL, AUX, COM1)."""
    p = Path(raw_str)
    for part in p.parts:
        clean_part = part.rstrip(". ")
        stem = Path(clean_part).stem.upper()
        if stem in DOS_DEVICE_NAMES:
            return True
    return False


def has_alternate_data_stream(raw_str: str) -> bool:
    """Detects NTFS Alternate Data Stream notation or colon not belonging to an ASCII drive prefix."""
    is_ascii_drive = (
        len(raw_str) >= 2
        and raw_str[1] == ":"
        and raw_str[0].isascii()
        and raw_str[0].isalpha()
    )
    if is_ascii_drive:
        return ":" in raw_str[2:]
    return ":" in raw_str


def confine(
    path: Union[str, Path, None],
    kind: str = "workspace",
    allow_create: bool = False,
    base_dir: Optional[Path] = None,
    trusted_roots: Optional[List[Path]] = None,
) -> Path:
    """
    Confines and canonicalizes a path against vetted roots.

    Args:
        path: Path string or Path object to validate.
        kind: Target type ('workspace', 'vault', 'file', or 'any').
        allow_create: If True, parent must exist and be confined, file need not exist yet.
        base_dir: Base directory for resolving relative paths (default: first trusted workspace or CWD).
        trusted_roots: Optional explicit list of trusted root Paths.

    Returns:
        Resolved canonical Path.

    Raises:
        ValueError: If path is empty or contains malformed syntax.
        PermissionError: If path violates root boundaries, UNC restrictions, or escapes trusted roots.
        FileNotFoundError: If path does not exist and allow_create is False.
    """
    if path is None or not str(path).strip():
        raise ValueError("Path argument cannot be empty or None.")

    raw_str = str(path).strip().strip("\"'")

    # 1. Reject UNC paths immediately
    if is_unc_path(raw_str):
        raise PermissionError(f"UNC path '{raw_str}' is forbidden for security.")

    # 2. Reject drive-relative paths (e.g. 'C:foo.txt')
    if is_drive_relative(raw_str):
        raise PermissionError(f"Drive-relative path '{raw_str}' is forbidden. Use fully qualified absolute or standard relative paths.")

    # 3. Reject NTFS alternate data streams
    if has_alternate_data_stream(raw_str):
        raise PermissionError(f"NTFS Alternate Data Stream '{raw_str}' is forbidden.")

    # 4. Reject DOS reserved device names
    if is_dos_device_name(raw_str):
        raise PermissionError(f"Windows reserved device name in '{raw_str}' is forbidden.")

    # 5. Reject drive root / filesystem root directly
    p = Path(raw_str)
    if is_root_drive(p):
        raise PermissionError(f"Filesystem root '{raw_str}' cannot be targeted as a confined workspace or file.")

    # 4. Determine approved root roots based on kind
    configured_workspaces = list(get_trusted_workspaces())
    for extra in _EXTRA_TRUSTED_WORKSPACES:
        if extra not in configured_workspaces:
            configured_workspaces.append(extra)

    vault_root = get_vault_path()

    if trusted_roots is not None:
        roots = list(trusted_roots)
    elif kind == "vault":
        roots = [vault_root]
    elif kind == "workspace":
        roots = configured_workspaces
    else:  # 'file' or 'any'
        roots = list(configured_workspaces)
        if vault_root not in roots:
            roots.append(vault_root)

    if not roots:
        roots = [Path.cwd().resolve()]

    # Default base for relative resolution
    effective_base = base_dir.resolve() if base_dir else (roots[0] if roots else Path.cwd().resolve())

    # 5. Canonical resolution (resolves symlinks and junctions to underlying physical targets)
    target = p if p.is_absolute() else (effective_base / p)
    try:
        resolved = target.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise PermissionError(f"Failed to resolve path '{raw_str}': {e}")

    # Re-check root drive after canonical resolution
    if is_root_drive(resolved):
        raise PermissionError(f"Resolved path '{resolved}' points to a filesystem root.")

    # 6. Verify containment inside approved roots BEFORE existence checks
    if not is_path_under_roots(resolved, roots):
        raise PermissionError(
            f"Path '{raw_str}' resolves to '{resolved}', which is outside approved roots: {[str(r) for r in roots]}."
        )

    # 7. For vault kind, ensure no hidden directory segments (.obsidian, etc.)
    if kind == "vault":
        try:
            rel_parts = resolved.relative_to(vault_root).parts
            if any(part.startswith(".") for part in rel_parts):
                raise PermissionError(f"Vault path '{raw_str}' accesses hidden or restricted segments.")
        except ValueError:
            pass

    # 8. If allow_create is False, ensure target actually exists
    if not allow_create and not resolved.exists():
        raise FileNotFoundError(f"Target path '{raw_str}' does not exist.")

    return resolved
