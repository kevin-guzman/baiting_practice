from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Optional


VolumeCallback = Callable[[str], None]


class UsbListener(ABC):

    def __init__(self) -> None:
        self._on_volume_mounted: Optional[VolumeCallback] = None

    def set_on_volume_mounted(self, callback: VolumeCallback) -> None:
        self._on_volume_mounted = callback

    @abstractmethod
    def start(self) -> None:
        """Inicia el monitoreo (no bloqueante)."""

    @abstractmethod
    def stop(self) -> None:
        """Detiene el monitoreo y libera recursos."""
