from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


project_root = Path(SPECPATH).parent
hidden_imports = (
    collect_submodules("customtkinter")
    + collect_submodules("keyring.backends")
    + ["pystray._base", "pystray._xorg"]
)
data_files = collect_data_files("customtkinter")
python_library = Path(sys.base_prefix) / "lib"
tcl_tk_binaries = [
    (str(python_library / "libtcl9.0.so"), "."),
    (str(python_library / "libtcl9tk9.0.so"), "."),
]

analysis = Analysis(
    [str(project_root / "run.py")],
    pathex=[str(project_root)],
    binaries=tcl_tk_binaries,
    datas=data_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "pytest_cov"],
    noarchive=False,
    optimize=1,
)
python_archive = PYZ(analysis.pure)

executable = EXE(
    python_archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="cryptosafe-manager",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
)

distribution = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="CryptoSafeManager",
)
