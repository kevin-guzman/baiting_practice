from __future__ import annotations

import threading
import time
from pathlib import Path

from usb_guard.listener import UsbListener
from usb_guard.storage import get_removable_volume_paths

_VOLUMES = Path("/Volumes")


class MacOsUsbListener(UsbListener):
    """
    macOS: sondeo de /Volumes.

    Watchdog/FSEvents suele no notificar (o hacerlo de forma poco fiable) la
    aparición de nuevos volúmenes USB; el sondeo es el enfoque estable.
    """

    def __init__(self, poll_interval: float = 1.0) -> None:
        super().__init__()
        self._poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: set[str] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if not _VOLUMES.is_dir():
            raise RuntimeError("No existe /Volumes; ¿es este sistema macOS?")

        self._known = get_removable_volume_paths()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._poll_interval):
            current = get_removable_volume_paths()
            new = current - self._known
            self._known = current
            for mount_path in new:
                time.sleep(0.7)
                cb = self._on_volume_mounted
                if cb:
                    cb(mount_path)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
