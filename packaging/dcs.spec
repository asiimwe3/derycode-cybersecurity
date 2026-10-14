# Derycode Cybersecurity — PyInstaller build (Stage 8)
# Build:  pyinstaller packaging/dcs.spec
# Output: dist/DerycodeCybersecurity/ (portable folder)

import sys
from pathlib import Path

block_cipher = None
PROJECT = Path(SPECPATH).parent

a = Analysis(
    [str(PROJECT / "main.py")],
    pathex=[str(PROJECT)],
    binaries=[],
    datas=[
        (str(PROJECT / "README.md"), "."),
        (str(PROJECT / "packaging"), "packaging"),
    ],
    hiddenimports=["PySide6.QtPrintSupport"],
    hookspath=[],
    excludes=["tkinter", "unittest", "pydoc"],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DerycodeCybersecurity",
    debug=False,
    strip=False,
    upx=False,
    console=False,          # windowed application
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="DerycodeCybersecurity",
)
