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
"""DST 专用服务器管理：扫描本地存档、解析模组、拉起分片进程。

只依赖标准库（winreg / subprocess / re / pathlib），与本项目其它模块保持一致。

数据来源（2026-09-22 实测）：
- 存档：``Documents\\Klei\\DoNotStarveTogether\\<ownerdir>\\<Cluster_N>\\``
- 模组开关：``<shard>\\modoverrides.lua``（Lua 表，``["workshop-<id>"]={enabled=..., configuration_options={...}}``）
- 模组名称：``<workshop>\\content\\322330\\<id>\\modinfo.lua`` 的 ``name = "..."``；次选
  ``<game>\\mods\\workshop-<id>\\modinfo.lua`` 与 ``<game>\\cached_mods\\<id>_\\d+\\modinfo.lua``
- 分片就绪标志：日志里出现 ``[IPC] Signal 'DST_Master_Ready' opened`` 或
  ``DST_Secondary_Ready``（见 ``master_server_log.txt`` 实测）
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import threading
import time
import winreg
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

APPID = "322330"
# 64 位与 32 位 nullrenderer 共用同一个文件名基础部分（bin64/ 是 _x64、bin/ 无后缀）。
NULLRENDERER_BASENAME = "dontstarve_dedicated_server_nullrenderer"
# 历史兼容：旧代码只认 x64 名字
NULLRENDERER_NAME = NULLRENDERER_BASENAME + "_x64.exe"


# ---------------------------------------------------------------------------
# 用户设置（环境覆盖）
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    """用户在界面上手动指定的路径，解决环境探测不到的边界情况。"""

    game_dir: str = ""          # 含 bin64\ 的游戏目录（如 ...\common\Don't Starve Together）
    storage_root: str = ""      # -persistent_storage_root（APP:Klei/ 或绝对路径）
    conf_dir: str = ""          # -conf_dir（默认 DoNotStarveTogether）
    extra_args: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.game_dir or self.storage_root or self.conf_dir or self.extra_args)


_settings = Settings()
_settings_loaded = False


def settings() -> Settings:
    """返回当前设置；首次访问时自动从磁盘加载。"""
    global _settings, _settings_loaded
    if not _settings_loaded:
        _settings = load_settings()
        _settings_loaded = True
    return _settings


def set_settings(s: Settings) -> None:
    global _settings, _settings_loaded
    _settings = s
    _settings_loaded = True


def _appdata_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return Path(base) / "DST-IP-Join"


def load_settings() -> Settings:
    """从 %APPDATA%\\DST-IP-Join\\settings.json 读取设置；缺省或损坏则返回默认值。"""
    path = _appdata_dir() / "settings.json"
    if not path.is_file():
        return Settings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Settings(
            game_dir=str(data.get("game_dir", "") or ""),
            storage_root=str(data.get("storage_root", "") or ""),
            conf_dir=str(data.get("conf_dir", "") or ""),
            extra_args=[str(x) for x in data.get("extra_args", []) if isinstance(x, str)],
        )
    except (OSError, ValueError, TypeError):
        return Settings()


def save_settings(s: Settings) -> None:
    """保存设置到 %APPDATA%\\DST-IP-Join\\settings.json。"""
    d = _appdata_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "settings.json").write_text(
        json.dumps({
            "game_dir": s.game_dir,
            "storage_root": s.storage_root,
            "conf_dir": s.conf_dir,
            "extra_args": s.extra_args,
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

_MOD_KEY_RE = re.compile(r'\["([^"]+)"\]\s*=\s*\{')
_ENABLED_RE = re.compile(r'\benabled\s*=\s*true\b')
_NAME_RE = re.compile(r'^\s*name\s*=\s*"((?:[^"\\]|\\.)*)"', re.MULTILINE)
_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]*)"', re.MULTILINE)
_SERVER_PORT_RE = re.compile(r'^\s*server_port\s*=\s*(\d+)', re.MULTILINE)
_IS_MASTER_RE = re.compile(r'^\s*is_master\s*=\s*true\b', re.MULTILINE)
# 配置项计数：只数 configuration_options={...} 内部的「键=」，单行/多行写法都适用
_CFG_BLOCK_RE = re.compile(r'configuration_options\s*=\s*\{(.*?)\}\s*,?\s*enabled', re.DOTALL)
_CFG_KEY_RE = re.compile(r'[A-Za-z_]\w*\s*=')
# 分片就绪标志（sigprefix 默认 Master→DST_Master、Caves→DST_Secondary）
_READY_RE = re.compile(r"\bDST_(?:Master|Secondary)_Ready\b")
# 分片刚开监听的标志（外挂进程早已就绪、不会再打 Ready，只能靠这行判断存活）
_STARTED_RE = re.compile(r"Server Started on port")
# 命令行参数值（PS CIM 拿到的原始命令行）
_ARG_RE_CACHE: dict[str, re.Pattern] = {}


def _arg(cmdline: str, name: str) -> str | None:
    """从命令行文本里取 ``-name value`` 的 value（不含引号内空格的简单场景够用）。"""
    pat = _ARG_RE_CACHE.get(name)
    if pat is None:
        pat = re.compile(rf"-{re.escape(name)}\s+(\S+)")
        _ARG_RE_CACHE[name] = pat
    m = pat.search(cmdline)
    return m.group(1) if m else None


class ServerError(Exception):
    """服务器相关操作的统一异常。"""


# ---------------------------------------------------------------------------
# Windows 已知文件夹（解决「文档」被 OneDrive 重定向的问题）
# ---------------------------------------------------------------------------

# FOLDERID_Documents = {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
_FOLDERID_DOCUMENTS = bytes([
    0xD0, 0x9A, 0xD3, 0xFD, 0x8F, 0x23, 0xAF, 0x46,
    0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7,
])


def documents_dir() -> Path:
    """返回真实的「文档」目录（可能被 OneDrive 重定向）。

    别用 ``Path.home() / 'Documents'`` —— 一旦用户开了 OneDrive 同步，
    文档的实际位置就变成 ``C:\\Users\\x\\OneDrive\\Documents``。
    官方做法是 ``SHGetKnownFolderPath(FOLDERID_Documents)``；失败才回退。
    """
    try:
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        ole32 = ctypes.windll.ole32      # type: ignore[attr-defined]
        shell32.SHGetKnownFolderPath.argtypes = (
            wintypes.LPCGUID, wintypes.DWORD, wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_wchar_p),
        )
        shell32.SHGetKnownFolderPath.restype = wintypes.HRESULT
        ptr = ctypes.c_wchar_p()
        hr = shell32.SHGetKnownFolderPath(
            _FOLDERID_DOCUMENTS, 0, None, ctypes.byref(ptr))
        if hr == 0 and ptr.value:
            path = Path(ptr.value)
            ole32.CoTaskMemFree(ptr)
            return path
    except (OSError, AttributeError, ValueError):
        pass
    return Path.home() / "Documents"


# ---------------------------------------------------------------------------
# Steam / 游戏安装目录定位
# ---------------------------------------------------------------------------

def _read_steam_path() -> Path | None:
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for sub in (r"Software\Valve\Steam", r"SOFTWARE\WOW6432Node\Valve\Steam"):
            try:
                with winreg.OpenKey(root, sub) as key:
                    value, _ = winreg.QueryValueEx(key, "SteamPath")
                    if value:
                        return Path(str(value).replace("/", "\\"))
            except OSError:
                continue
    return None


def _library_folders(vdf: Path) -> list[Path]:
    text = vdf.read_text(encoding="utf-8", errors="replace")
    return [Path(m.replace("\\\\", "\\")) for m in re.findall(r'"path"\s+"([^"]+)"', text)]


def _is_game_dir(p: Path) -> bool:
    """一个目录是否是合法的 DST 游戏目录（含 bin64\\ 或 bin\\）。"""
    return p.is_dir() and ((p / "bin64").is_dir() or (p / "bin").is_dir())


def _nullrenderer(game_dir: Path) -> Path | None:
    """找到 nullrenderer 可执行文件。

    优先级：bin64\\_x64 → bin\\（32 位）→ bin64\\（无后缀，旧版布局）。
    """
    for rel in (
        Path("bin64") / (NULLRENDERER_BASENAME + "_x64.exe"),
        Path("bin") / (NULLRENDERER_BASENAME + ".exe"),
        Path("bin64") / (NULLRENDERER_BASENAME + ".exe"),
    ):
        p = game_dir / rel
        if p.is_file():
            return p
    return None


def find_dst_install() -> tuple[Path, Path] | None:
    """定位 DST 安装目录与创意工坊目录。

    返回 ``(game_dir, workshop_dir)``；``workshop_dir`` 是
    ``<lib>\\steamapps\\workshop``（传给 ``-ugc_directory`` 的就是它，
    游戏内部再拼 ``content\\322330``）。找不到返回 ``None``。

    规则：
    - 用户若在设置里指定了 ``game_dir``，以那个为准；
    - 否则依次尝试：Steam 注册表 → 各库下的标准布局（64 位客户端、
      32 位客户端、Beta 分支、独立的专用服务器安装）。
    """
    # 1) 用户手动指定
    custom = settings().game_dir.strip()
    if custom:
        g = Path(custom)
        if _is_game_dir(g):
            # 工坊目录尽量从同一库推断；推不出来就用游戏目录自身（让 -ugc_directory 至少可传）
            workshop = g
            for _ in range(4):  # 最多向上找 4 层，找含 steamapps\\workshop 的
                parent = workshop.parent
                if (workshop / "steamapps" / "workshop").is_dir():
                    return g, workshop / "steamapps" / "workshop"
                if parent == workshop:
                    break
                workshop = parent
            return g, g
        # 用户填错路径时给出明确报错而不是静默失败
        raise ServerError(
            f"设置里的游戏目录不是有效的饥荒联机版目录（缺 bin64\\ 或 bin\\）：{custom}"
        )

    # 2) Steam 注册表 + 库扫描
    steam = _read_steam_path()
    if steam is None:
        return None
    candidates = [steam]
    vdf = steam / "steamapps" / "libraryfolders.vdf"
    if vdf.is_file():
        candidates += _library_folders(vdf)
    seen: set[str] = set()
    for lib in candidates:
        key = str(lib).lower()
        if key in seen:
            continue
        seen.add(key)
        common = lib / "steamapps" / "common"
        if not common.is_dir():
            continue
        # 标准客户端 / Beta 分支 / 独立专用服务器
        for sub in (
            "Don't Starve Together",
            "Don't Starve Together Beta",
            "Don't Starve Together Dedicated Server",
        ):
            game = common / sub
            if _is_game_dir(game):
                return game, lib / "steamapps" / "workshop"
    return None


# ---------------------------------------------------------------------------
# 模组解析
# ---------------------------------------------------------------------------

@dataclass
class ModInfo:
    id: str                     # 纯数字 ID，如 "2189004162"
    name: str = ""
    version: str = ""
    enabled: bool = True
    config_count: int = 0
    installed: bool = True      # workshop/content/<appid>/<id> 目录是否存在
    path: Path | None = None    # 实际模组目录（用于读 modinfo）

    @property
    def display_name(self) -> str:
        return self.name or f"workshop-{self.id}"


def _parse_modinfo(text: str) -> tuple[str, str]:
    """从 modinfo.lua 文本提取 (name, version)。"""
    name_m = _NAME_RE.search(text)
    ver_m = _VERSION_RE.search(text)
    name = name_m.group(1) if name_m else ""
    return name, (ver_m.group(1) if ver_m else "")


def _find_mod_dirs(mod_id: str, *, workshop_content: Path | None,
                   game_dir: Path | None) -> list[Path]:
    """按优先级列出该模组可能的安装目录。"""
    candidates: list[Path] = []
    if workshop_content is not None:
        candidates.append(workshop_content / mod_id)
    if game_dir is not None:
        candidates.append(game_dir / "mods" / f"workshop-{mod_id}")
        cached = game_dir / "cached_mods"
        if cached.is_dir():
            try:
                subs = sorted((d for d in cached.iterdir()
                               if d.is_dir() and d.name.startswith(mod_id + "_")),
                              key=lambda d: d.name)
                candidates.extend(subs)
            except OSError:
                pass
    return [d for d in candidates if d.is_dir()]


def parse_modoverrides(text: str, *, workshop_content: Path | None = None,
                       game_dir: Path | None = None) -> list[ModInfo]:
    """解析 modoverrides.lua，返回启用的模组列表。"""
    starts = [(m.start(), m.group(1)) for m in _MOD_KEY_RE.finditer(text)]
    mods: list[ModInfo] = []
    for i, (pos, key) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        block = text[pos:end]
        if not _ENABLED_RE.search(block):
            continue
        mod_id = key.replace("workshop-", "")
        cfg_m = _CFG_BLOCK_RE.search(block)
        config_count = len(_CFG_KEY_RE.findall(cfg_m.group(1))) if cfg_m else 0

        mod = ModInfo(id=mod_id, config_count=config_count)
        dirs = _find_mod_dirs(mod_id, workshop_content=workshop_content, game_dir=game_dir)
        mod.installed = bool(dirs)
        mod.path = dirs[0] if dirs else None
        if mod.path is not None:
            info = mod.path / "modinfo.lua"
            if info.is_file():
                mod.name, mod.version = _parse_modinfo(
                    info.read_text(encoding="utf-8", errors="replace"))
        mods.append(mod)
    return mods


# ---------------------------------------------------------------------------
# 存档（集群）扫描
# ---------------------------------------------------------------------------

@dataclass
class ShardInfo:
    name: str                   # "Master" / "Caves" 等
    is_master: bool
    port: int | None
    path: Path

    @property
    def log_path(self) -> Path:
        return self.path / "server_log.txt"


@dataclass
class ClusterInfo:
    name: str                   # 目录名，如 "Cluster_2"
    path: Path
    ownerdir: Path              # .../<ownerdir>/ 目录（如 1071833019）
    shards: list[ShardInfo] = field(default_factory=list)
    mods: list[ModInfo] = field(default_factory=list)
    has_token: bool = False
    cluster_name: str = ""
    description: str = ""
    lan_only: bool = False          # cluster.ini 的 lan_only_cluster
    confdir: str = "DoNotStarveTogether"   # 所属存档根（稳定版或 Beta 分支）

    @property
    def owner_id(self) -> str:
        return self.ownerdir.name

    def master(self) -> ShardInfo | None:
        return next((s for s in self.shards if s.is_master), None)

    def ports(self) -> list[int]:
        return [s.port for s in self.shards if s.port is not None]

    def missing_mods(self) -> list[ModInfo]:
        return [m for m in self.mods if not m.installed]

    def summary(self) -> str:
        ports = "/".join(str(p) for p in self.ports()) or "?"
        token = "有" if self.has_token else "缺"
        mods = f"{len(self.mods)} 个模组"
        missing = self.missing_mods()
        if missing:
            mods += f"（{len(missing)} 个未下载）"
        return f"{self.cluster_name}  ·  端口 {ports}  ·  令牌{token}  ·  {mods}"


def klei_root() -> Path:
    """Klei 存档根目录（默认 ``<Documents>\\Klei``）。

    用户可在设置里指定 ``storage_root`` 覆盖（比如把存档放到了 D 盘）。
    """
    override = settings().storage_root.strip()
    if override:
        p = Path(override)
        # 允许直接指到 ...\\Klei 或 ...\\Documents（自动补一层 Klei）
        if (p / "DoNotStarveTogether").is_dir():
            return p
        if (p / "Klei").is_dir():
            return p / "Klei"
        return p
    return documents_dir() / "Klei"


# 历史兼容名（保持旧调用不报错）
def _klei_root() -> Path:
    return klei_root()


def conf_dir_name() -> str:
    """-conf_dir 的值（默认 DoNotStarveTogether；Beta 分支是 DoNotStarveTogetherBetaBranch）。"""
    override = settings().conf_dir.strip()
    return override or "DoNotStarveTogether"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_ini(text: str) -> dict[str, str]:
    """把 INI 文本摊平成 ``section.key -> value``。"""
    out: dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
        elif "=" in line:
            key, _, value = line.partition("=")
            out[f"{section}.{key.strip().lower()}"] = value.strip()
    return out


def scan_cluster(path: Path, *, workshop_content: Path | None = None,
                 game_dir: Path | None = None) -> ClusterInfo | None:
    """扫描单个集群目录；不是合法集群（无 cluster.ini）返回 ``None``。"""
    cluster_ini = path / "cluster.ini"
    if not cluster_ini.is_file():
        return None

    info = ClusterInfo(name=path.name, path=path, ownerdir=path.parent)
    info.confdir = path.parent.parent.name  # .../<Klei>/<confdir>/<ownerdir>/<cluster>
    ini = _parse_ini(_read(cluster_ini))
    info.cluster_name = ini.get("network.cluster_name", path.name)
    info.description = ini.get("network.cluster_description", "")
    info.lan_only = ini.get("network.lan_only_cluster", "").strip().lower() == "true"

    token = path / "cluster_token.txt"
    info.has_token = token.is_file() and token.stat().st_size > 0

    for sub in sorted(path.iterdir()):
        if not sub.is_dir():
            continue
        server_ini = sub / "server.ini"
        if not server_ini.is_file():
            continue
        text = _read(server_ini)
        port_m = _SERVER_PORT_RE.search(text)
        info.shards.append(ShardInfo(
            name=sub.name,
            is_master=_IS_MASTER_RE.search(text) is not None,
            port=int(port_m.group(1)) if port_m else None,
            path=sub,
        ))
    info.shards.sort(key=lambda s: (not s.is_master, s.name))

    # 模组配置写在分片目录下（Master 优先，否则第一个有的分片）
    mo_shard = next((s for s in info.shards if (s.path / "modoverrides.lua").is_file()), None)
    if mo_shard is not None:
        info.mods = parse_modoverrides(
            _read(mo_shard.path / "modoverrides.lua"),
            workshop_content=workshop_content, game_dir=game_dir)
    return info


# 可能的存档根：稳定版 + Beta 分支（游戏内分别写各自的 Cluster_N）
_CONFDIR_CANDIDATES = ("DoNotStarveTogether", "DoNotStarveTogetherBetaBranch")


def scan_clusters(klei_root: Path | None = None, *,
                  workshop_content: Path | None = None,
                  game_dir: Path | None = None) -> list[ClusterInfo]:
    """扫描本机所有饥荒存档集群。

    会同时扫描稳定版（``DoNotStarveTogether``）与 Beta 分支
    （``DoNotStarveTogetherBetaBranch``）两个存档根；重名的集群会都列出，
    但各自的 ``ownerdir`` 不同（区分依据）。
    """
    root = klei_root or _klei_root()
    out: list[ClusterInfo] = []
    seen: set[str] = set()
    for confdir in _CONFDIR_CANDIDATES:
        base = root / confdir
        if not base.is_dir():
            continue
        try:
            ownerdirs = sorted(p for p in base.iterdir()
                               if p.is_dir() and p.name != "backup")
        except OSError:
            continue
        for ownerdir in ownerdirs:
            try:
                clusters = sorted(ownerdir.iterdir())
            except OSError:
                continue
            for cluster in clusters:
                if not cluster.is_dir():
                    continue
                key = str(cluster).lower()
                if key in seen:
                    continue
                seen.add(key)
                info = scan_cluster(cluster, workshop_content=workshop_content,
                                    game_dir=game_dir)
                if info is not None:
                    out.append(info)
    return out


# ---------------------------------------------------------------------------
# 分片进程与服务器管理
# ---------------------------------------------------------------------------

class ShardProcess:
    """单个分片进程（Master 或 Caves）。

    日志从 **stdout** 实时捕获（nullrenderer 会把日志同时写到 stdout 与
    ``server_log.txt``，但写文件是缓冲的，启动早期读文件可能迟迟看不到
    就绪行），用后台线程持续读取，避免管道缓冲区满导致子进程阻塞。
    """

    def __init__(self, cluster: ClusterInfo, shard: ShardInfo, *,
                 game_dir: Path, ugc_dir: Path,
                 update_mods: bool = False,
                 extra_args: list[str] | None = None) -> None:
        self.cluster = cluster
        self.shard = shard
        self.game_dir = game_dir
        self.args = self._build_args(game_dir, ugc_dir, update_mods, extra_args)
        # cwd 取 exe 实际所在目录（bin64/ 或 bin/）
        self.cwd = Path(self.args[0]).parent
        self.proc: subprocess.Popen | None = None
        self._buf: list[str] = []
        self._emit_offset = 0
        self._ready = False
        self._reader: threading.Thread | None = None
        self._started_pid: int | None = None
        self._stdin_lock = threading.Lock()

    def _build_args(self, game_dir: Path, ugc_dir: Path, update_mods: bool,
                    extra_args: list[str] | None) -> list[str]:
        exe = _nullrenderer(game_dir)
        if exe is None:
            raise ServerError(
                f"在游戏目录里找不到专用服务器可执行文件：{game_dir}"
                "（需要 bin64\\dontstarve_dedicated_server_nullrenderer_x64.exe 或 32 位 bin\\ 版本）"
            )
        storage_root = settings().storage_root.strip() or "APP:Klei/"
        # 该集群实际所在的存档根（稳定版 or Beta 分支）；用户可用 conf_dir 强制覆盖
        conf = settings().conf_dir.strip() or self.cluster.confdir
        args = [
            str(exe),
            "-cluster", self.cluster.name,
            "-shard", self.shard.name,
            "-persistent_storage_root", storage_root,
            "-conf_dir", conf,
            "-ownerdir", self.cluster.owner_id,
            "-ugc_directory", str(ugc_dir),
        ]
        # 与游戏客户端拉起分片时的传参保持一致：
        #   Master → -sigprefix DST_Master  -secondary_log_prefix master
        #   Caves  → -sigprefix DST_Secondary -secondary_log_prefix caves
        # IPC 就绪信号名 = <sigprefix>_Ready；不传 sigprefix 时信号名不可预测，
        # 会导致“服务器其实已监听端口、但 DST_Master_Ready 一直不出现”的假卡死。
        if self.shard.is_master:
            args += ["-sigprefix", "DST_Master", "-secondary_log_prefix", "master"]
        else:
            args += ["-sigprefix", "DST_Secondary", "-secondary_log_prefix", "caves"]
        args.append("-only_update_server_mods" if update_mods else "-skip_update_server_mods")
        if extra_args:
            args.extend(extra_args)
        # 服务器控制台：console_enabled=false 时 -console 也能把输入通道打开
        # （exe 原文：'-console has been deprecated: Use the [MISC] / console_enabled
        # setting instead.'——只是弃用警告，功能仍生效；不传时受 console_enabled 门控）
        args.append("-console")
        return args

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def exit_code(self) -> int | None:
        return self.proc.poll() if self.proc is not None else None

    def start(self) -> None:
        if self.alive:
            return
        self._buf = []
        self._emit_offset = 0
        self._ready = False
        self.proc = subprocess.Popen(
            self.args,
            cwd=str(self.cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._reader.start()
        self._started_pid = self.proc.pid

    def _pump_stdout(self) -> None:
        """后台线程：持续读 stdout，逐行判断就绪标志。"""
        assert self.proc is not None and self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                line = line.rstrip("\n")
                self._buf.append(line)
                if not self._ready and _READY_RE.search(line):
                    self._ready = True
        except (OSError, ValueError):
            # 进程结束 / 管道关闭
            pass

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.alive:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        self.proc = None

    def send_command(self, command: str) -> tuple[bool, str]:
        """向该分片的 stdin 写一行 Lua 指令（需要 -console 启动）。

        返回 ``(是否成功, 说明)``。注意 nullrenderer **不回显**输入行，
        指令产生的输出会稍后出现在 stdout 里（由 pump() 读走）。
        """
        command = (command or "").strip()
        if not command:
            return False, "指令为空"
        proc = self.proc
        if proc is None or not self.alive:
            return False, f"{self.shard.name} 未在运行"
        stdin = proc.stdin
        if stdin is None:
            return False, "stdin 不可用（不是本工具启动的进程？）"
        try:
            with self._stdin_lock:
                stdin.write(command + "\n")
                stdin.flush()
        except (OSError, ValueError) as exc:
            return False, f"写入失败：{exc}"
        return True, f"→ {self.shard.name}: {command}"

    def pump(self) -> str:
        """读取日志增量（非阻塞），返回新增文本。"""
        new = self._buf[self._emit_offset:]
        self._emit_offset = len(self._buf)
        return "\n".join(new)

    def is_ready(self) -> bool:
        """分片是否就绪（启动后是否打出了 *_Ready 信号）。"""
        return self._ready

    def tail(self, n: int = 12) -> str:
        """最近 n 行日志（用于报错时展示）。"""
        return "\n".join(self._buf[-n:])


class ServerManager:
    """管理一个集群的所有分片进程。"""

    def __init__(self, cluster: ClusterInfo, *,
                 game_dir: Path | None = None,
                 ugc_dir: Path | None = None,
                 update_mods: bool = False,
                 offline: bool | None = None,
                 extra_args: list[str] | None = None) -> None:
        if game_dir is None or ugc_dir is None:
            found = find_dst_install()
            if not found:
                raise ServerError("未找到饥荒联机版安装目录（Steam 库扫描失败）")
            game_dir, ugc_dir = found
        self.cluster = cluster
        # 局域网集群（lan_only_cluster=true）默认走 -offline：跳过 Klei 云存档同步，
        # 否则启动会卡在反复重试的 500（E_ROWID_EXISTS）上一直出不了就绪信号。
        # 显式传 offline=False 可强制走在线（需要 Klei 云存档接口可用）。
        self.offline = cluster.lan_only if offline is None else offline
        args = list(extra_args or [])
        if self.offline:
            args.append("-offline")
        self.procs: list[ShardProcess] = [
            ShardProcess(cluster, shard, game_dir=game_dir, ugc_dir=ugc_dir,
                         update_mods=update_mods, extra_args=args)
            for shard in cluster.shards
        ]
        if not self.procs:
            raise ServerError(f"集群 {cluster.name} 下没有任何分片（server.ini）")

    # -- 进程控制 -----------------------------------------------------------

    def start_all(self, *, wait_ready: bool = True, timeout: float = 150.0,
                  callback=None) -> None:
        """先起 Master，就绪后再起其余分片。

        ``callback(stage, text)`` 用于回报进度；stage ∈ {"info", "ready", "fail"}。
        """
        def note(stage: str, text: str) -> None:
            if callback:
                callback(stage, text)

        master = next((p for p in self.procs if p.shard.is_master), self.procs[0])
        others = [p for p in self.procs if p is not master]

        note("info", f"启动主分片 {master.shard.name}（端口 {master.shard.port}）…")
        master.start()
        if wait_ready and not self._wait_ready(master, timeout, note):
            master.stop()
            raise ServerError(f"主分片 {master.shard.name} 在 {timeout:.0f}s 内未就绪")

        for proc in others:
            note("info", f"启动分片 {proc.shard.name}（端口 {proc.shard.port}）…")
            proc.start()
            if wait_ready:
                self._wait_ready(proc, timeout, note)

    def _wait_ready(self, proc: ShardProcess, timeout: float, note) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.is_ready():
                note("ready", f"{proc.shard.name} 就绪（DST_*_Ready）")
                return True
            if not proc.alive:
                note("fail", f"{proc.shard.name} 已退出，exit={proc.exit_code}\n{proc.tail()}")
                return False
            time.sleep(0.4)
        note("fail", f"{proc.shard.name} 等待就绪超时")
        return False

    def stop_all(self) -> None:
        # 先停次级分片，最后停 Master，避免分片写脏数据
        for proc in sorted(self.procs, key=lambda p: p.shard.is_master):
            proc.stop()

    # -- 状态 ---------------------------------------------------------------

    def any_running(self) -> bool:
        return any(p.alive for p in self.procs)

    def pump_logs(self) -> str:
        """返回所有分片的日志增量。"""
        parts = []
        for proc in self.procs:
            chunk = proc.pump()
            if chunk:
                for line in chunk.splitlines():
                    if line.strip():
                        parts.append(f"[{proc.shard.name}] {line}")
        return "\n".join(parts)

    def send_command(self, command: str, shard: str = "") -> tuple[bool, str]:
        """向指定分片（默认主世界）的 stdin 发送 Lua 指令。

        返回 ``(是否成功, 说明)``。失败原因通常是「没在运行」或
        「该分片不是本工具启动的（没有 stdin）」。
        """
        command = (command or "").strip()
        if not command:
            return False, "指令为空"
        proc = (next((p for p in self.procs if p.shard.name == shard), None)
                if shard else self.master_proc())
        if proc is None:
            names = "、".join(p.shard.name for p in self.procs)
            return False, f"没有叫 {shard!r} 的分片（现有：{names}）"
        return proc.send_command(command)

    def master_proc(self) -> ShardProcess | None:
        return next((p for p in self.procs if p.shard.is_master), None)

    def status(self) -> list[dict]:
        return [{
            "shard": p.shard.name,
            "is_master": p.shard.is_master,
            "port": p.shard.port,
            "running": p.alive,
            "ready": p.is_ready() if p.alive else False,
            "exit_code": p.exit_code,
        } for p in self.procs]


# ---------------------------------------------------------------------------
# 便捷入口
# ---------------------------------------------------------------------------

def default_install() -> tuple[Path, Path]:
    """找到游戏安装与工坊目录，失败抛 ServerError。"""
    found = find_dst_install()
    if not found:
        raise ServerError(
            "未找到饥荒联机版安装目录（Steam 库扫描失败）。"
            "可在「开服」标签页里手动指定游戏目录。"
        )
    return found


def workshop_content_dir(workshop_dir: Path) -> Path:
    """``<workshop>\\content\\322330``。"""
    return workshop_dir / "content" / APPID


# ---------------------------------------------------------------------------
# 开服 Token（cluster_token.txt）
# ---------------------------------------------------------------------------

# 粗略校验：Klei 令牌是一段较长的 base64 类字符串，不含空白
_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")


def validate_token(text: str) -> tuple[bool, str]:
    """校验用户粘贴的令牌内容。返回 ``(ok, 规范化的令牌或错误信息)``。"""
    token = (text or "").strip()
    if not token:
        return False, "令牌为空"
    # 允许用户把从 zip/网页复制的多行/带空白内容整段粘进来，取第一个合法 token
    for cand in re.split(r"[\s]+", token):
        if _TOKEN_RE.match(cand):
            return True, cand
    return False, "内容不像合法的 Klei 令牌（应为一段无空白的长字符串）"


def write_token(cluster: ClusterInfo, token: str) -> Path:
    """把令牌以**二进制**写入集群的 ``cluster_token.txt``（绝不多带换行）。

    若已存在且内容一致则不动；不一致先备份为 ``.bak``。
    """
    data = token.encode("utf-8")
    dest = cluster.path / "cluster_token.txt"
    if dest.exists():
        old = dest.read_bytes()
        if old == data:
            return dest
        backup = dest.with_suffix(".txt.bak")
        backup.write_bytes(old)
    dest.write_bytes(data)
    cluster.has_token = True
    return dest


# ---------------------------------------------------------------------------
# 服务器控制台（stdin 远程指令）
# ---------------------------------------------------------------------------

def console_enabled(cluster: ClusterInfo) -> bool:
    """该存档的 ``cluster.ini`` 是否开了 ``[MISC] console_enabled``。

    只有开了它，专用服务器才受理从 stdin 进来的 Lua 指令
    （本工具启动时会补传 ``-console``，两道门都打开才稳）。
    """
    try:
        ini = _parse_ini(_read(cluster.path / "cluster.ini"))
    except OSError:
        return False
    return ini.get("misc.console_enabled", "").strip().lower() == "true"


def enable_console(cluster: ClusterInfo) -> tuple[bool, str]:
    """给存档的 ``cluster.ini`` 补写 ``[MISC] console_enabled = true``。

    - 已开启 → ``(True, "已开启")``，文件不动；
    - 已有 ``[MISC]`` 段 → 段末插一行；
    - 没有 → 文件末尾追加整段。
    写前会先备份为 ``cluster.ini.bak``。返回 ``(是否成功, 说明)``。
    """
    ini_path = cluster.path / "cluster.ini"
    try:
        text = _read(ini_path)
    except OSError as exc:
        return False, f"读取 cluster.ini 失败：{exc}"

    lines = text.splitlines()
    misc_idx = None
    for i, raw in enumerate(lines):
        if raw.strip().lower() == "[misc]":
            misc_idx = i
            break

    if misc_idx is not None:
        # 段内是否已有 console_enabled（大小写不敏感）
        found = False
        for i in range(misc_idx + 1, len(lines)):
            stripped = lines[i].strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                break  # 进入下一个段
            if stripped.lower().startswith("console_enabled"):
                if stripped.split("=", 1)[-1].strip().lower() == "true":
                    return True, "已开启"
                lines[i] = "console_enabled = true"
                found = True
                break
        if not found:
            # 插到该段**真正的末尾**（下一个段头或空行前的最后一个键之后），
            # 而不是段头下面一行 —— 紧贴段头插入会把段内已有键挤到后面，
            # 视觉上像键属于别的段；对 INI 解析无碍，但 diff 阅读体验差。
            insert_at = misc_idx + 1
            for i in range(misc_idx + 1, len(lines)):
                stripped = lines[i].strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    break
                if stripped:
                    insert_at = i + 1
            lines.insert(insert_at, "console_enabled = true")
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("[MISC]")
        lines.append("console_enabled = true")

    new_text = "\n".join(lines) + "\n"
    try:
        backup = ini_path.with_suffix(".ini.bak")
        backup.write_text(text, encoding="utf-8")
        ini_path.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return False, f"写入 cluster.ini 失败：{exc}"
    return True, "已补写 console_enabled = true（备份为 cluster.ini.bak）"


# ---------------------------------------------------------------------------
# 玩家名单（blocklist.txt / adminlist.txt）：每行一个 Klei 用户 ID
# ---------------------------------------------------------------------------

# Klei 用户 ID：KU_ 前缀 + 一段非空白字符（可能是中文等任意字符）
_BLOCKLIST_RE = re.compile(r"^KU_\S+$")


def parse_player_lines(text: str) -> list[dict]:
    """从服务器日志文本里抠出 ``c_listallplayers()`` 打印的玩家行。

    输出格式（consolecommands.lua:291）：``[1] (KU_abCd1234) 玩家名 <角色prefab>``；
    界面日志泵会给行加上分片前缀（``[Master] [1] (...) ...``），所以容忍任意多个
    ``[xxx]`` 前缀；玩家名可能含任意字符，按「] (」与「) <」锚点切。
    """
    players: list[dict] = []
    for line in text.splitlines():
        m = _PLAYER_LINE_RE.match(line.strip())
        if not m:
            continue
        players.append({
            "index": int(m.group(1)),
            "userid": m.group(2),
            "name": m.group(3),
            "prefab": m.group(4),
        })
    return players


# 解析玩家行：[分片前缀]* [时间戳]:? [序号] (用户ID) 玩家名 <角色prefab>
# 实测（2026-09-23，用户真实服务器）：
#   [Master] [00:07:09]: [1] (OU_76561199032098747) SLDYK <wortox>
# 要点：① ID 前缀不止 KU_，还有 OU_（Steam 数字 ID 换算）等，别按前缀白名单；
#      ② 时间戳后面有冒号；③ 行尾可能有制表符。
_PLAYER_LINE_RE = re.compile(
    r"^(?:\[[^\]]*\]\s*:?)*\s*\[(\d+)\]\s*\(([^()]+)\)\s*(.*?)\s*<([^<>]+)>\s*$")


# ---------------------------------------------------------------------------
# 服务器暂停/继续（TheSim:SetTimeScale）
# ---------------------------------------------------------------------------

# 🔴 为什么不是 TheNet:SetServerPaused：那是「客户端暂停菜单」的语义开关，
# 在专用服务器上执行后世界照跑（2026-09-23 用户实测：连发三次，
# RemoteCommandInput 确认送达且无报错，但没有任何 Sim paused/unpaused 转换）。
# 专用服务器真正的暂停 = 时间刻度 0；引擎的 pause_when_empty 自动暂停就是
# 这么实现的，切换时引擎自己会打印 `Sim paused` / `Sim unpaused`。
PAUSE_ON_CMD = "TheSim:SetTimeScale(0)"
PAUSE_OFF_CMD = "TheSim:SetTimeScale(1)"
# 状态未知时的切换：单条表达式取反（老坑：两条语句挤一行没有分隔符 =
# Lua 语法错误，指令根本不执行）。
PAUSE_TOGGLE_CMD = "TheSim:SetTimeScale(TheSim:GetTimeScale() > 0 and 0 or 1)"

# 状态打点前缀。服务器**不回显**输入行，暂停是否生效只能让游戏自己 print
# 出当前时间刻度（0 = 已暂停）。世界暂停时 stdin 控制台仍会处理指令（实测）。
SIM_TIMESCALE_PREFIX = "DSTIPJ_SIM_TS="
SIM_TIMESCALE_PROBE_TEMPLATE = (
    f'print("{SIM_TIMESCALE_PREFIX}" .. tostring(TheSim:GetTimeScale()))')

_SIM_TIMESCALE_RE = re.compile(
    re.escape(SIM_TIMESCALE_PREFIX) + r"\s*([0-9.eE+-]+)")
_SIM_ENGINE_RE = re.compile(r"\bSim (un)?paused\b")


def parse_sim_timescale(text: str) -> float | None:
    """日志文本里最近一条时间刻度打点的值；没有打点返回 None。"""
    value: float | None = None
    for m in _SIM_TIMESCALE_RE.finditer(text):
        try:
            value = float(m.group(1))
        except ValueError:
            continue
    return value


def parse_pause_state(text: str) -> bool | None:
    """从日志文本解析「世界模拟是否暂停」。

    两种来源，按文本顺序取**最后**一条：
    - 打点行 ``DSTIPJ_SIM_TS=<值>``：0 = 暂停，非 0 = 运行；
    - 引擎原生行 ``Sim paused`` / ``Sim unpaused``（含 pause_when_empty
      人数清空时的自动暂停：最后一名玩家退出会打出 Sim paused）。
    没有任何线索时返回 None（调用方保持现有状态、按钮保持中性文案）。
    """
    value: bool | None = None
    for line in text.splitlines():
        m = _SIM_TIMESCALE_RE.search(line)
        if m is not None:
            try:
                value = float(m.group(1)) == 0.0
                continue
            except ValueError:
                pass
        em = _SIM_ENGINE_RE.search(line)
        if em is not None:
            value = em.group(1) is None  # 没有 un 前缀 = paused
    return value


_ENGINE_TS_RE = re.compile(r"\[(\d{1,2}):([0-5]?\d):([0-5]?\d)\]")


def engine_timestamp(line: str) -> int | None:
    """引擎日志行 ``[HH:MM:SS]:`` 的时间戳（换算成秒）；没有返回 None。

    容忍日志泵加的 ``[Master]`` 分片前缀（分片名不含数字冒号，不会误配）。
    用途：日志视图有块数上限、旧内容会被驱逐，文本长度不单调，
    「这条回显是否发生在发指令之后」只能靠引擎时间戳判断。
    """
    m = _ENGINE_TS_RE.search(line)
    if m is None:
        return None
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))


def add_blocklist_userid(cluster: ClusterInfo, userid: str) -> tuple[bool, str]:
    """把一个 Klei 用户 ID 追加进存档根的 ``blocklist.txt``（去重，幂等）。

    DST 服务器在玩家加入时校验 blocklist：名单内用户直接拒连。
    只追加不删除（清理黑名单让用户自己编辑文件）。返回 ``(是否新增, 说明)``。
    """
    userid = (userid or "").strip()
    if not _BLOCKLIST_RE.match(userid):
        return False, f"不像合法的 Klei 用户 ID：{userid!r}"
    path = cluster.path / "blocklist.txt"
    try:
        existing = path.read_text(encoding="utf-8", errors="replace").splitlines() \
            if path.is_file() else []
        if userid in {line.strip() for line in existing}:
            return True, f"{userid} 已在黑名单里"
        with path.open("a", encoding="utf-8") as f:
            if existing and existing[-1].strip():
                f.write("\n")
            f.write(userid + "\n")
    except OSError as exc:
        return False, f"写入 blocklist.txt 失败：{exc}"
    return True, f"已把 {userid} 写入黑名单（下次连接即拒）"


# ---------------------------------------------------------------------------
# 接管：发现已在运行的专用服务器并监控/停止它
# ---------------------------------------------------------------------------

# 解析 ``APP:Klei/`` 这类别名 → 绝对路径
def _resolve_storage_root(raw: str | None) -> Path:
    """把 ``-persistent_storage_root`` 的值解析成绝对路径。

    ``APP:Klei/`` 是 Klei 内置别名，等价于 ``<Documents>\\Klei``。
    """
    raw = (raw or "").strip().strip('"')
    if not raw or raw.upper().startswith("APP:KLEI"):
        return documents_dir() / "Klei"
    return Path(raw)


@dataclass
class ShardProcInfo:
    """一条运行中的分片进程。"""

    pid: int
    name: str                     # exe 文件名
    cmdline: str
    exe_path: Path | None = None
    cluster_name: str = ""
    shard_name: str = ""
    confdir: str = "DoNotStarveTogether"
    ownerdir: str = ""
    is_master: bool = False

    @property
    def game_dir(self) -> Path | None:
        return self.exe_path.parent.parent if self.exe_path else None


def list_running_shard_procs() -> list[ShardProcInfo]:
    """枚举当前运行中的 nullrenderer 分片进程（WMI/CIM 查询）。

    只匹配进程名含 ``dontstarve_dedicated_server_nullrenderer`` 的，
    不把客户端（dontstarve_steam）算进来。
    """
    ps = (
        "Get-CimInstance Win32_Process "
        "-Filter \"name like '%dontstarve_dedicated_server_nullrenderer%'\" | "
        "Select-Object ProcessId,Name,CommandLine,ExecutablePath | ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    txt = out.stdout.strip()
    if not txt:
        return []
    try:
        data = json.loads(txt)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    out: list[ShardProcInfo] = []
    for item in data:
        name = str(item.get("Name") or "")
        if NULLRENDERER_BASENAME not in name.lower():
            continue
        cmdline = str(item.get("CommandLine") or "")
        exe = item.get("ExecutablePath")
        info = ShardProcInfo(
            pid=int(item.get("ProcessId") or 0),
            name=name,
            cmdline=cmdline,
            exe_path=Path(exe) if exe else None,
            cluster_name=_arg(cmdline, "cluster") or "",
            shard_name=_arg(cmdline, "shard") or "",
            confdir=_arg(cmdline, "conf_dir") or "DoNotStarveTogether",
            ownerdir=_arg(cmdline, "ownerdir") or "",
            is_master=(_arg(cmdline, "sigprefix") or "").endswith("Master"),
        )
        out.append(info)
    return out


def _pid_alive(pid: int) -> bool:
    """进程是否还活着。

    不能只看 ``OpenProcess`` 成功与否 —— 进程被 ``taskkill`` 后，其内核对象在
    句柄完全释放前仍可被打开（端口已不监听、进程其实在退出），会误判成活着。
    要用 ``GetExitCodeProcess`` 看退出码是否仍为 STILL_ACTIVE(259)。
    """
    if pid <= 0:
        return False
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, wintypes.LPDWORD)
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h = kernel32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        code = wintypes.DWORD()
        ok = kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        kernel32.CloseHandle(h)
        # STILL_ACTIVE = 259；已终止的进程会拿到真实退出码
        return bool(ok) and code.value == 259
    except (OSError, AttributeError):
        return False


def attach_running_procs(clusters: list[ClusterInfo] | None = None,
                         procs: list[ShardProcInfo] | None = None) -> AttachedServer | None:
    """把运行中的分片进程按集群分组，返回一个可监控/可停止的接管对象。

    匹配规则：
    - 优先按 ``-ownerdir + -cluster`` 与已扫描到的存档精确匹配；
    - 找不到匹配存档（比如用户手动启动、存档被移走）时，返回 ``cluster=None``
      的接管对象，只能监控/停止，不能补模组信息。
    """
    procs = procs if procs is not None else list_running_shard_procs()
    if not procs:
        return None

    # 按 (ownerdir, cluster) 分组；同一集群的多个分片算一个服务器
    groups: dict[tuple[str, str], list[ShardProcInfo]] = {}
    for p in procs:
        groups.setdefault((p.ownerdir, p.cluster_name), []).append(p)

    # 取进程数最多的那一组（正常情况只有一组）
    key, members = max(groups.items(), key=lambda kv: len(kv[1]))
    ownerdir, cluster_name = key

    cluster: ClusterInfo | None = None
    if clusters:
        cluster = next(
            (c for c in clusters if c.name == cluster_name and c.owner_id == ownerdir),
            None,
        )
        if cluster is None:
            # ownerdir 可能为空（手动启动没传 -ownerdir），退化为只按集群名匹配
            cluster = next((c for c in clusters if c.name == cluster_name), None)

    shards: list[RunningShard] = []
    for p in members:
        shard: ShardInfo | None = None
        if cluster is not None:
            shard = next((s for s in cluster.shards if s.name == p.shard_name), None)
        shards.append(RunningShard(p, cluster, shard))
    return AttachedServer(cluster, shards)


class RunningShard:
    """对一个**非本工具启动**的分片进程的监控视图。"""

    def __init__(self, proc: ShardProcInfo, cluster: ClusterInfo | None,
                 shard: ShardInfo | None) -> None:
        self.proc_info = proc
        self.cluster = cluster
        self.shard = shard
        self._log_path = self._find_log()
        self._log_offset = self._log_path.stat().st_size if self._log_path and self._log_path.exists() else 0

    # -- 日志定位 -----------------------------------------------------------

    def _find_log(self) -> Path | None:
        # 1) 用命令行参数精确推导
        root = _resolve_storage_root(_arg(self.proc_info.cmdline, "persistent_storage_root"))
        confdir = self.proc_info.confdir or "DoNotStarveTogether"
        for ownerdir, cluster_name, shard_name in (
            (self.proc_info.ownerdir, self.proc_info.cluster_name, self.proc_info.shard_name),
        ):
            p = root / confdir / ownerdir / cluster_name / shard_name / "server_log.txt"
            if p.is_file():
                return p
        # 2) 用已匹配的存档对象
        if self.shard is not None:
            p = self.shard.log_path
            if p.is_file():
                return p
        return None

    # -- 状态 ---------------------------------------------------------------

    @property
    def alive(self) -> bool:
        return _pid_alive(self.proc_info.pid)

    @property
    def is_master(self) -> bool:
        if self.shard is not None:
            return self.shard.is_master
        return self.proc_info.is_master

    @property
    def port(self) -> int | None:
        return self.shard.port if self.shard is not None else None

    def is_ready(self) -> bool:
        """外挂进程早就绪了（不会再打 *_Ready），以「存活 + 日志存在」近似。"""
        return self.alive

    def pump(self) -> str:
        """读 server_log.txt 的增量（外挂进程没有 stdout 可读）。"""
        if self._log_path is None or not self._log_path.exists():
            return ""
        try:
            with self._log_path.open("rb") as f:
                f.seek(self._log_offset)
                data = f.read(512 * 1024)
                self._log_offset = f.tell()
        except OSError:
            return ""
        return data.decode("utf-8", errors="replace")

    def tail(self, n: int = 12) -> str:
        if self._log_path is None or not self._log_path.exists():
            return ""
        try:
            lines = self._log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return "\n".join(lines[-n:])

    def stop(self) -> None:
        """停止该分片进程（taskkill /T 终止整棵进程树）。"""
        if not self.alive:
            return
        try:
            subprocess.run(
                ["taskkill", "/PID", str(self.proc_info.pid), "/T", "/F"],
                capture_output=True, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


class AttachedServer:
    """对一个已在运行的服务器的接管句柄（只监控/停止，**不会重复启动**）。"""

    def __init__(self, cluster: ClusterInfo | None, shards: list[RunningShard]) -> None:
        self.cluster = cluster
        self.shards = shards
        self.attached = True   # 标记：这是接管而非本工具启动的

    # -- 状态（接口与 ServerManager 对齐，方便 GUI 复用） --------------------

    def any_running(self) -> bool:
        return any(s.alive for s in self.shards)

    def pump_logs(self) -> str:
        parts = []
        for s in self.shards:
            chunk = s.pump()
            if chunk:
                for line in chunk.splitlines():
                    if line.strip():
                        parts.append(f"[{s.proc_info.shard_name or '?'}] {line}")
        return "\n".join(parts)

    def status(self) -> list[dict]:
        return [{
            "shard": s.proc_info.shard_name or "?",
            "is_master": s.is_master,
            "port": s.port,
            "running": s.alive,
            "ready": s.is_ready() if s.alive else False,
            "pid": s.proc_info.pid,
            "attached": True,
        } for s in self.shards]

    def send_command(self, command: str, shard: str = "") -> tuple[bool, str]:
        """接管的外部进程拿不到 stdin，指令一律拒绝（说清楚原因）。"""
        return False, "接管的外部服务器无法接收指令（stdin 不在本工具手里）\n" \
                      "请在它自己的控制台窗口输入，或改用本工具启动服务器"

    def stop_all(self) -> None:
        # 先停次级分片，最后停 Master
        for s in sorted(self.shards, key=lambda x: x.is_master):
            s.stop()
