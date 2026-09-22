# -*- coding: utf-8 -*-
"""Nuitka 打包脚本：把 GUI 编译成单文件 exe。

为什么用 Python 而不是直接写在 .bat 里：exe 名字含中文，而 cmd.exe 按 cp936
解码 .bat，写中文会乱码。这里源码是 UTF-8，中文名字安全。

用法（一般由 build.bat 调用）：
    .venv\\Scripts\\python.exe build_nuitka.py
    .venv\\Scripts\\python.exe build_nuitka.py --no-onefile   # 目录版，启动更快
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENTRY = os.path.join(HERE, "main.py")
ICON = os.path.join(HERE, "assets", "icon.ico")
DIST = os.path.join(HERE, "dist")
EXE_NAME = "饥荒IP联机助手.exe"
APP_NAME = "饥荒联机版 IP 联机助手"
COMPANY = "SLDYK"


def read_version() -> str:
    """从 dst_ip_join/config.py 里读 APP_VERSION，避免两处版本号不一致。"""
    path = os.path.join(HERE, "dst_ip_join", "config.py")
    try:
        with open(path, encoding="utf-8") as handle:
            match = re.search(
                r'^APP_VERSION\s*=\s*["\']([^"\']+)', handle.read(), re.MULTILINE
            )
        if match:
            return match.group(1)
    except OSError:
        pass
    return "1.0.0"


def build_command(onefile: bool, jobs: int | None) -> list[str]:
    version = read_version()
    # Windows 版本资源需要 4 段数字，1.0.0 -> 1.0.0.0
    numeric = (version + ".0.0.0").split(".")[:4]
    numeric_version = ".".join(numeric)

    args = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--enable-plugin=pyqt6",
        # 无控制台的窗口程序（Nuitka 4.x 用这个选项，旧的 --windows-disable-console 已弃用）
        "--windows-console-mode=disable",
        f"--windows-icon-from-ico={ICON}",
        f"--output-dir={DIST}",
        "--assume-yes-for-downloads",
        # 体积：排掉本程序用不到的兜底与科学计算栈
        "--nofollow-import-to=tkinter",
        "--nofollow-import-to=matplotlib",
        "--nofollow-import-to=numpy",
        "--nofollow-import-to=pytest",
        # exe 版本信息
        f"--company-name={COMPANY}",
        f"--product-name={APP_NAME}",
        f"--file-description={APP_NAME}",
        f"--copyright=Copyright (C) {time.strftime('%Y')} {COMPANY}",
        f"--file-version={numeric_version}",
        f"--product-version={numeric_version}",
    ]

    if onefile:
        args += [
            "--onefile",
            f"--output-filename={EXE_NAME}",
            # 单文件解包到固定缓存目录：便于排查，也避免每次换随机名触发杀软
            "--onefile-tempdir-spec={CACHE_DIR}/DST_IP_Helper/{VERSION}",
        ]

    if jobs:
        args.append(f"--jobs={jobs}")

    args.append(ENTRY)
    return args


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="用 Nuitka 打包饥荒 IP 联机助手")
    parser.add_argument(
        "--no-onefile",
        action="store_true",
        help="产出目录版（dist\\main.dist），启动更快、便于调试",
    )
    parser.add_argument(
        "--keep-output",
        action="store_true",
        help="保留中间产物（默认清理），排查编译问题时有用",
    )
    parser.add_argument("--jobs", type=int, default=0, help="并行编译进程数，默认让 Nuitka 决定")
    args = parser.parse_args(argv)

    for path, what in ((ENTRY, "入口 main.py"), (ICON, "图标 assets/icon.ico")):
        if not os.path.exists(path):
            print(f"[ERROR] 找不到{what}：{path}")
            return 1

    onefile = not args.no_onefile
    command = build_command(onefile, args.jobs or None)
    if not args.keep_output:
        command.insert(-1, "--remove-output")

    print("=" * 72)
    print(f"Nuitka 打包 {APP_NAME} v{read_version()}")
    print("  模式：", "单文件 onefile" if onefile else "目录版 standalone")
    print("  产物：", os.path.join("dist", EXE_NAME) if onefile else "dist\\main.dist\\")
    print("  提示：首次编译较慢（通常几分钟），请耐心等待。")
    print("=" * 72)

    started = time.monotonic()
    try:
        code = subprocess.call(command, cwd=HERE)
    except KeyboardInterrupt:
        print("\n[已中断]")
        return 130
    elapsed = time.monotonic() - started

    if code != 0:
        print(f"\n[ERROR] Nuitka 构建失败（退出码 {code}），耗时 {elapsed:.0f} 秒")
        return code

    print(f"\n[OK] 构建完成，耗时 {elapsed:.0f} 秒")
    if onefile:
        out = os.path.join(DIST, EXE_NAME)
        if os.path.exists(out):
            size = os.path.getsize(out) / 1024 / 1024
            print(f"     产物：{out}（{size:.1f} MB）")
    else:
        print(f"     产物目录：{os.path.join(DIST, 'main.dist')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
