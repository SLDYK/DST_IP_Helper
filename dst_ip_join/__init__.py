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
"""饥荒联机版 IP 联机助手 —— 核心包。

只依赖 Python 标准库。
"""

from .config import APP_NAME, APP_VERSION

__all__ = ["APP_NAME", "APP_VERSION"]
