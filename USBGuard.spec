# -*- mode: python ; coding: utf-8 -*-
# Genera un único binario. Ejecutar en el SO destino:
#   pyinstaller USBGuard.spec
#
# macOS: dist/USBGuard
# Windows: dist/USBGuard.exe

import sys

block_cipher = None

_hidden = [
    "usb_guard",
    "usb_guard.app",
    "usb_guard.listener",
    "usb_guard.storage",
    "usb_guard.baiting_analyzer",
]
if sys.platform == "win32":
    _hidden.append("usb_guard.windows_listener")
else:
    _hidden.append("usb_guard.macos_listener")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="USBGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # True: ves errores y logs en consola. Cambia a False para solo ventana (sin terminal).
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
