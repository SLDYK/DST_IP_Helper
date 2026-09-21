# -*- coding: utf-8 -*-
"""命令行入口。

用法：
    python cli.py                  # 完整检测并自动配置
    python cli.py --dry-run        # 只检测，不修改防火墙 / UPnP
    python cli.py --ports 10999    # 手动指定端口
    python cli.py --cleanup        # 撤销本工具添加的规则与映射
"""

from __future__ import annotations

import argparse
import os
import sys


def _bootstrap() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def _fix_console_encoding() -> None:
    """中文 Windows 控制台是 GBK，遇到生僻字符会抛 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _bootstrap()
    _fix_console_encoding()

    parser = argparse.ArgumentParser(
        prog="dst-ip-join",
        description="饥荒联机版 IP 联机助手（检测网络环境并自动配置端口映射）",
    )
    parser.add_argument(
        "--ports",
        help="手动指定端口，逗号分隔，例如 10999,10998；留空则自动识别",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只检测，不修改防火墙规则和 UPnP 端口映射",
    )
    parser.add_argument("--cleanup", action="store_true", help="撤销本工具添加的配置")
    parser.add_argument(
        "-y", "--yes", action="store_true", help="跳过撤销前的确认提示"
    )
    args = parser.parse_args(argv)

    from dst_ip_join import diagnostics

    def log(message: str) -> None:
        print(message, flush=True)

    if args.cleanup:
        if not args.yes:
            answer = input("将删除本工具添加的防火墙规则和 UPnP 映射，继续？[y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print("已取消")
                return 0
        diagnostics.cleanup(log=log)
        return 0

    ports: list[int] | None = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.replace("，", ",").split(",") if p.strip()]
        except ValueError:
            print(f"端口格式不对：{args.ports}")
            return 2

    report = diagnostics.run_diagnosis(
        ports=ports,
        log=log,
        configure=not args.dry_run,
    )

    print()
    print(report.share_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
