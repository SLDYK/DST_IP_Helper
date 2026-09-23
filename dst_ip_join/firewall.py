# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 SLDYK
#
# 本程序是自由软件：你可以遵照 GNU 通用公共许可证第 3 版
# （GPL-3.0-only）的条款重新发布和/或修改它。
#
# 本程序基于「有用」的期望分发，但不提供任何担保；连适销性或
# 特定用途适用性的默示担保也没有。完整条款见仓库根目录的
# LICENSE 文件，或 <https://www.gnu.org/licenses/>。
"""Windows 防火墙放行规则管理（通过 netsh，需要管理员权限）。

只增删自己创建的规则（名字带 config.FIREWALL_RULE_PREFIX 前缀），
不会碰系统里已有的饥荒规则，也不会碰其他程序。
"""

from __future__ import annotations

import subprocess

from . import config, winproc

# 判断 netsh 报错的常见特征串（中英双语都覆盖）
_ELEVATION_HINTS = (
    "请求的操作需要提升",
    "requires elevation",
    "需要提升",
    "access is denied",
    "拒绝访问",
)

_NOT_FOUND_HINTS = (
    "没有与指定标准相匹配的规则",
    "no rules match",
    "没有与指定条件相符的规则",
)


def _decode(raw: bytes) -> str:
    """netsh 在中文 Windows 上输出 GBK，这里做一次尽力而为的解码。"""
    for encoding in ("gbk", "utf-8", "cp936"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _run_netsh(args: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["netsh"] + args,
            capture_output=True,
            creationflags=winproc.CREATE_NO_WINDOW,
        )
    except FileNotFoundError:
        return -1, "找不到 netsh 命令"
    except OSError as exc:
        return -1, str(exc)

    output = (_decode(proc.stdout or b"") + _decode(proc.stderr or b"")).strip()
    return proc.returncode, output


def rule_name(port: int) -> str:
    return f"{config.FIREWALL_RULE_PREFIX}-UDP-{port}"


def _looks_like_elevation_error(text: str) -> bool:
    lowered = text.lower()
    return any(hint.lower() in lowered for hint in _ELEVATION_HINTS)


def rule_exists(port: int) -> bool:
    code, output = _run_netsh(
        ["advfirewall", "firewall", "show", "rule", f"name={rule_name(port)}"]
    )
    if code == 0:
        return True
    lowered = output.lower()
    if any(hint.lower() in lowered for hint in _NOT_FOUND_HINTS):
        return False
    # 查询也可能因为权限失败，无法确定时保守返回 False
    return False


def add_udp_rule(port: int) -> tuple[bool, str]:
    """添加入站放行规则。返回 (是否成功, 说明文本)。"""
    name = rule_name(port)
    code, output = _run_netsh(
        [
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            "dir=in",
            "action=allow",
            "protocol=UDP",
            f"localport={port}",
            "profile=any",
            "enable=yes",
        ]
    )

    if code == 0:
        return True, f"已放行入站 UDP {port}"
    if _looks_like_elevation_error(output):
        return False, f"需要管理员权限才能放行 UDP {port}"
    return False, f"放行 UDP {port} 失败：{output.splitlines()[0] if output else '未知错误'}"


def remove_udp_rule(port: int) -> tuple[bool, str]:
    """删除本工具创建的放行规则。"""
    name = rule_name(port)
    code, output = _run_netsh(
        ["advfirewall", "firewall", "delete", "rule", f"name={name}"]
    )

    if code == 0:
        return True, f"已删除 UDP {port} 放行规则"
    lowered = output.lower()
    if any(hint.lower() in lowered for hint in _NOT_FOUND_HINTS):
        return True, f"UDP {port} 规则本就不存在"
    if _looks_like_elevation_error(output):
        return False, f"需要管理员权限才能删除 UDP {port} 规则"
    return False, f"删除 UDP {port} 规则失败：{output.splitlines()[0] if output else '未知错误'}"
