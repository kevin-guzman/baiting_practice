from __future__ import annotations

import threading
import time
from pathlib import Path

from usb_guard.listener import UsbListener
from usb_guard.storage import get_removable_volume_paths


class WindowsUsbListener(UsbListener):
    """
    Windows: sondeo de unidades extraíbles (GetDriveType).
    Evita dependencias extra; intervalo corto para detectar inserciones.
    """

    def __init__(self, poll_interval: float = 1.25) -> None:
        super().__init__()
        self._poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: set[str] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._known = get_removable_volume_paths()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._poll_interval):
            current = get_removable_volume_paths()
            new = current - self._known
            self._known = current
            for drive in new:
                # Dar tiempo a que el volumen esté listo
                time.sleep(0.8)
                path = str(Path(drive))
                cb = self._on_volume_mounted
                if cb:
                    cb(path)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
