# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

构建：.venv\\Scripts\\pyinstaller.exe build_exe.spec --noconfirm
产物：dist\\饥荒IP联机助手.exe（单文件、无控制台、内嵌图标）
"""

import os

block_cipher = None
HERE = os.path.dirname(os.path.abspath(SPEC))

a = Analysis(
    ["main.py"],
    pathex=[HERE],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # 减小体积 / 避免误打包：
        "tkinter",          # 界面用 PyQt6（main.py 里 Tkinter 仅作兜底，PyQt6 存在时不会 import）
        "matplotlib",
        "numpy",
        "pytest",
        "setuptools",
        "pip",
    ],
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
    name="饥荒IP联机助手",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                 # GUI 程序，不显示控制台
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(HERE, "assets", "icon.ico"),
    # PyInstaller 会自动给 exe 加上 admin 清单（uac_admin 不是必需，
    # 程序内部用 ShellExecuteW("runas") 按需提权，因此保持 asInvoker 由用户选择）。
    uac_admin=False,
)
