from __future__ import annotations

import os
import re
import stat
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List


# Extensiones típicas de ejecución / engaño en USB baiting
_WIN_EXEC = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".dll", ".cpl"}
_WIN_SHORTCUT = {".lnk", ".url"}
_WIN_SCRIPT = {".vbs", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psc1"}
_MAC_APP = {".app", ".command", ".dmg", ".pkg"}
_SCRIPT_UNIX = {".sh", ".bash", ".zsh", ".py", ".pl", ".rb"}

SUSPICIOUS_ROOT_NAMES = {
    "open",
    "click",
    "install",
    "setup",
    "readme",
    "document",
    "photo",
    "pictures",
    "important",
}


@dataclass
class BaitingReport:
    """Resultado del análisis heurístico."""

    path: str
    risk_score: int
    reasons: List[str] = field(default_factory=list)
    suspicious_files: List[str] = field(default_factory=list)

    @property
    def is_potentially_malicious(self) -> bool:
        return self.risk_score >= 40


def _is_hidden_posix(path: Path) -> bool:
    name = path.name
    if name.startswith("."):
        return True
    uf = getattr(stat, "UF_HIDDEN", 0)
    if not uf:
        return False
    try:
        st = path.lstat()
        if hasattr(st, "st_flags"):
            return bool(st.st_flags & uf)
    except OSError:
        pass
    return False


def _is_hidden_windows(path: Path) -> bool:
    import sys

    if sys.platform != "win32":
        return _is_hidden_posix(path)
    try:
        import ctypes

        FILE_ATTRIBUTE_HIDDEN = 0x2
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
        if attrs == 0xFFFFFFFF:
            return False
        return bool(attrs & FILE_ATTRIBUTE_HIDDEN)
    except OSError:
        return False


def _double_extension(name: str) -> bool:
    """Detecta nombres tipo foto.jpg.exe."""
    dangerous = _WIN_EXEC | _WIN_SHORTCUT | _WIN_SCRIPT | _MAC_APP
    p = Path(name)
    suf = p.suffix.lower()
    if suf not in dangerous:
        return False
    stem = p.stem
    return "." in stem


def _read_autorun_inf_snippet(path: Path, max_bytes: int = 8192) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
        # autorun.inf suele ser ASCII / UTF-16 LE
        if data.startswith(b"\xff\xfe"):
            return data.decode("utf-16-le", errors="replace")
        return data.decode("latin-1", errors="replace")
    except OSError:
        return ""


def _score_autorun(content: str) -> tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    lower = content.lower()
    if "open=" in lower or "shellexecute=" in lower:
        score += 45
        reasons.append("autorun.inf referencia ejecución automática (open/shellexecute).")
    if "icon=" in lower and ".exe" in lower:
        score += 25
        reasons.append("autorun.inf asocia icono a un ejecutable.")
    if "action=" in lower and "run" in lower:
        score += 15
        reasons.append("autorun.inf define acción de ejecución.")
    return score, reasons


def _iter_files_limited(root: Path, max_depth: int, max_files: int) -> Iterable[Path]:
    root = root.resolve()
    count = 0
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    while queue and count < max_files:
        current, depth = queue.popleft()
        try:
            for child in current.iterdir():
                if count >= max_files:
                    return
                yield child
                count += 1
                if child.is_dir() and depth < max_depth:
                    queue.append((child, depth + 1))
        except OSError:
            continue


class BaitingAnalyzer:
    """
    Heurísticas para USB baiting: ejecutables en raíz, accesos directos,
    dobles extensiones, autorun, archivos ocultos, muchos .lnk, etc.
    """

    def __init__(
        self,
        max_depth: int = 2,
        max_files: int = 400,
    ) -> None:
        self._max_depth = max_depth
        self._max_files = max_files

    def analyze(self, volume_root: str | os.PathLike[str]) -> BaitingReport:
        root = Path(volume_root)
        reasons: List[str] = []
        suspicious: List[str] = []
        score = 0

        if not root.is_dir():
            return BaitingReport(str(root), 0, ["No se pudo acceder al volumen."], [])

        is_win = os.name == "nt"
        hidden_check = _is_hidden_windows if is_win else _is_hidden_posix

        lnk_count = 0

        for fp in _iter_files_limited(root, self._max_depth, self._max_files):
            rel = str(fp.relative_to(root)) if fp != root else fp.name
            name_lower = fp.name.lower()

            if fp.is_file():
                suf = fp.suffix.lower()
                if suf in _WIN_EXEC or suf in _MAC_APP:
                    suspicious.append(rel)
                    if fp.parent == root:
                        score += 25
                        reasons.append(f"Ejecutable o binario en la raíz del volumen: {rel}")
                    else:
                        score += 8
                if suf in _WIN_SHORTCUT:
                    lnk_count += 1
                    suspicious.append(rel)
                    if fp.parent == root:
                        score += 12
                        reasons.append(f"Acceso directo o enlace en la raíz: {rel}")
                    else:
                        score += 4
                if suf in _WIN_SCRIPT or suf in _SCRIPT_UNIX:
                    suspicious.append(rel)
                    if fp.parent == root:
                        score += 18
                        reasons.append(f"Script potencialmente ejecutable en la raíz: {rel}")
                if _double_extension(fp.name):
                    score += 35
                    reasons.append(f"Posible doble extensión engañosa: {rel}")
                    suspicious.append(rel)
                if hidden_check(fp) and suf in (_WIN_EXEC | _WIN_SCRIPT | _SCRIPT_UNIX | _MAC_APP):
                    score += 30
                    reasons.append(f"Archivo ejecutable u oculto sospechoso: {rel}")
                    suspicious.append(rel)

            # autorun / desktop.ini en cualquier nivel bajo root (prioridad raíz)
            if fp.is_file() and name_lower == "autorun.inf":
                content = _read_autorun_inf_snippet(fp)
                s, rs = _score_autorun(content)
                score += s
                reasons.extend(rs)
                suspicious.append(rel)

        if lnk_count >= 5:
            score += 20
            reasons.append(f"Muchos accesos directos ({lnk_count}); patrón típico de baiting.")

        # Nombres en raíz que invitan a abrir
        try:
            for child in root.iterdir():
                if child.is_file():
                    stem = re.sub(r"[^a-z]+", "", child.stem.lower())
                    if any(s in stem for s in SUSPICIOUS_ROOT_NAMES) and child.suffix.lower() in (
                        _WIN_EXEC | _WIN_SHORTCUT | {".pdf", ".doc", ".docx"}
                    ):
                        score += 15
                        reasons.append(f"Nombre sugerente en raíz: {child.name}")
        except OSError:
            pass

        score = min(score, 100)
        report = BaitingReport(str(root), score, reasons, suspicious[:50])
        if not report.reasons and score == 0:
            report.reasons.append("No se detectaron indicadores fuertes de baiting (revisión superficial).")
        return report
