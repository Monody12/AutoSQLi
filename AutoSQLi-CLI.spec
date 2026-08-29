# -*- mode: python ; coding: utf-8 -*-
# CLI 版（console=True）：命令行回显正常输出。GUI 版见 AutoSQLi.spec。

a = Analysis(
    ['autosqli/cli_entry.py'],
    pathex=[],
    binaries=[],
    datas=[('autosqli/dictionaries', 'autosqli/dictionaries')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AutoSQLi-CLI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
