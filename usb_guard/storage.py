from __future__ import annotations

import os
import sys
from pathlib import Path


def get_removable_volume_paths() -> set[str]:
    """Rutas raíz de volúmenes extraíbles montados (Windows: letras; macOS: /Volumes/…)."""
    if sys.platform == "win32":
        return _win_removable_paths()
    if sys.platform == "darwin":
        return _mac_removable_paths()
    return set()


def _win_removable_paths() -> set[str]:
    import ctypes
    import string

    out: set[str] = set()
    DRIVE_REMOVABLE = 2
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        mask = kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if not (mask & (1 << i)):
                continue
            root = f"{letter}:\\"
            if kernel32.GetDriveTypeW(root) == DRIVE_REMOVABLE:
                out.add(str(Path(root)))
    except OSError:
        pass
    return out


def _mac_removable_paths() -> set[str]:
    out: set[str] = set()
    base = Path("/Volumes")
    try:
        for p in base.iterdir():
            if not p.is_dir():
                continue
            try:
                s = str(p.resolve())
            except OSError:
                s = str(p)
            if is_removable_storage_path(s):
                out.add(s)
    except OSError:
        pass
    return out


def is_removable_storage_path(path: str | os.PathLike[str]) -> bool:
    """
    Indica si la ruta parece un volumen de almacenamiento extraíble montado.
    No garantiza que sea USB físico (puede ser SD u otro removible).
    """
    p = Path(path)
    if sys.platform == "win32":
        return _win_is_removable_drive(p)
    if sys.platform == "darwin":
        return _mac_is_external_volume(p)
    return False


def _win_is_removable_drive(p: Path) -> bool:
    try:
        import ctypes

        DRIVE_REMOVABLE = 2
        root = f"{p.drive}\\" if p.drive else str(p)
        if len(root) < 2 or root[1] != ":":
            return False
        t = ctypes.windll.kernel32.GetDriveTypeW(root)  # type: ignore[attr-defined]
        return t == DRIVE_REMOVABLE
    except OSError:
        return False


def _mac_is_external_volume(p: Path) -> bool:
    try:
        resolved = p.resolve()
    except OSError:
        return False
    parts = resolved.parts
    if len(parts) >= 2 and parts[1] == "Volumes":
        # Excluir disco del sistema si estuviera bajo /Volumes (poco habitual)
        name = parts[2] if len(parts) > 2 else ""
        if name in ("Macintosh HD",):
            return False
        return True
    return False
