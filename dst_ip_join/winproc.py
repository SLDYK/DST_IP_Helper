# -*- coding: utf-8 -*-
"""Windows 原生能力封装（纯 ctypes，无第三方依赖）。

本模块提供：
  * 管理员权限检测 / 自我提权重启
  * 进程枚举与进程完整路径查询
  * UDP 端点表（拿到某进程真正监听的端口）
  * 本机 IPv4 地址枚举 / 默认出口本机 IP
  * 剪贴板写入
  * DPI 感知开启

设计要点（踩过的坑）：
  * 所有 64 位句柄相关的 argtypes / restype 必须显式声明，
    否则句柄会被 ctypes 默认按 int 截断成 32 位。
  * IP Helper 表里的端口字段是「网络字节序存在 DWORD 低 16 位」，
    需要 socket.ntohs 还原；地址字段是网络字节序，需要 struct.pack('<I')。
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass

from . import config

IS_WINDOWS = sys.platform == "win32"

# 让 subprocess 不弹出黑窗口
CREATE_NO_WINDOW = 0x08000000

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

AF_INET = 2
UDP_TABLE_OWNER_PID = 1

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


# ==========================================================================
# 懒加载的 DLL 句柄
# ==========================================================================
_dll_cache: dict[str, ctypes.WinDLL] = {}


def _dll(name: str) -> ctypes.WinDLL:
    dll = _dll_cache.get(name)
    if dll is None:
        dll = ctypes.WinDLL(name, use_last_error=True)
        _dll_cache[name] = dll
    return dll


# ==========================================================================
# 管理员权限
# ==========================================================================
def is_admin() -> bool:
    """当前进程是否以管理员身份运行。"""
    if not IS_WINDOWS:
        return False
    try:
        return bool(_dll("shell32").IsUserAnAdmin())
    except Exception:
        return False


def is_frozen() -> bool:
    """判断当前是否运行在打包后的 exe 里。

    多数打包器（PyInstaller / cx_Freeze / py2exe 等）会设 ``sys.frozen``，
    而 **Nuitka 不设**它 —— Nuitka 给每个被编译的模块注入 ``__compiled__`` 全局。
    两个都认，否则换打包器后提权重启会失效。
    """
    return bool(getattr(sys, "frozen", False)) or "__compiled__" in globals()


# ShellExecute 的返回值 <= 32 就是错误码（shellapi.h 的 SE_ERR_* 与部分 Win32 码混用）。
# 单独列出来，是因为提权失败时"到底为什么"全靠这个数字，而它很容易被丢掉。
_SHELL_EXEC_ERRORS = {
    0: "系统内存或资源不足",
    2: "找不到指定的文件",
    3: "找不到指定的路径",
    5: "系统拒绝了提权请求（可能被安全软件、组策略或父进程完整性级别拦截）",
    8: "系统内存不足",
    26: "文件共享冲突",
    27: "文件关联信息不完整",
    28: "DDE 会话超时",
    29: "DDE 事务失败",
    30: "DDE 服务繁忙",
    31: "没有可用的关联程序",
    32: "找不到所需的动态链接库",
    1223: "UAC 授权被取消（你点了「否」，或授权框超时自动关闭）",
}

# 这两个码都表示"用户侧没同意"，不该按故障来吓用户
_USER_DECLINED_CODES = (1223, 5)


def describe_shell_error(code: int) -> str:
    """把 ShellExecute 的错误码翻译成人话。"""
    return _SHELL_EXEC_ERRORS.get(code, f"未知错误（错误码 {code}）")


def is_valid_window(hwnd: int | None) -> bool:
    """句柄是否指向一个真实存在的窗口。

    作为 UAC 授权框的属主窗口，传一个**无效**句柄比传 NULL 更糟
    （授权框可能干脆不显示）。所以先校验，无效就退回 NULL。
    """
    if not hwnd:
        return False
    try:
        user32 = _dll("user32")
        user32.IsWindow.argtypes = (wintypes.HWND,)
        user32.IsWindow.restype = wintypes.BOOL
        return bool(user32.IsWindow(wintypes.HWND(int(hwnd))))
    except Exception:  # noqa: BLE001
        return False


@dataclass
class ElevationResult:
    """提权重启的结果。失败时必须带上错误码，否则无法排查。"""

    started: bool = False
    code: int = 0
    exe: str = ""
    params: str = ""
    detail: str = ""

    @property
    def message(self) -> str:
        if self.started:
            return "已以管理员权限重新启动"
        if self.code in _USER_DECLINED_CODES:
            return describe_shell_error(self.code)
        return f"提权失败：{describe_shell_error(self.code)}"

    @property
    def declined(self) -> bool:
        return (not self.started) and self.code in _USER_DECLINED_CODES


def build_elevation_command(extra_args: list[str] | None = None) -> tuple[str, str, str]:
    """算出提权时该启动什么：``(exe, 参数, 工作目录)``。

    单独抽出来是为了让它可测，也为了暴露一个真实易错点：
    ``sys.argv[0]`` 可能是**相对路径**（例如直接跑 ``python main.py``），
    而提权后新进程的工作目录不一定与当前一致，相对路径就会找不到脚本。
    所以这里一律转成绝对路径，并显式指定工作目录。
    """
    args = list(sys.argv[1:]) + list(extra_args or [])

    if is_frozen():
        # 打包成 exe 后：sys.executable 就是程序自身，
        # 直接以管理员身份重启 exe（不能再把 argv[0] 当脚本参数传入）。
        exe = os.path.abspath(sys.executable)
        params = subprocess.list2cmdline(args)
        workdir = os.path.dirname(exe)
    else:
        exe = sys.executable
        if not exe:
            return "", "", ""
        exe = os.path.abspath(exe)
        script = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
        params = subprocess.list2cmdline([script] + args)
        workdir = os.path.dirname(script) or os.getcwd()

    return exe, params, workdir


def request_admin_restart_detailed(
    extra_args: list[str] | None = None,
    hwnd: int | None = None,
) -> ElevationResult:
    """用 UAC 提权重新启动当前程序，并带上失败原因。

    与 :func:`request_admin_restart` 的区别是它不吞错误码 —— 提权失败时
    「为什么失败」是唯一有用的信息，必须能传到界面上。

    ``hwnd`` 是可选的本程序主窗口句柄，会作为 UAC 授权框的属主窗口。
    **不要留空**：传 NULL 时授权框可能无法正常置前显示（从终端启动时尤其明显），
    表现为「没看到授权框就直接失败」。
    """
    if not IS_WINDOWS:
        return ElevationResult(detail="当前系统不是 Windows")

    exe, params, workdir = build_elevation_command(extra_args)
    if not exe:
        return ElevationResult(code=2, detail="拿不到可执行文件路径")
    if not os.path.exists(exe):
        return ElevationResult(code=2, exe=exe, params=params,
                               detail=f"可执行文件不存在：{exe}")

    try:
        shell32 = _dll("shell32")
        shell32.ShellExecuteW.restype = wintypes.HINSTANCE
        shell32.ShellExecuteW.argtypes = (
            wintypes.HWND,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_int,
        )
        owner = wintypes.HWND(int(hwnd)) if is_valid_window(hwnd) else None
        ret = shell32.ShellExecuteW(owner, "runas", exe, params, workdir, 1)
    except Exception as exc:  # noqa: BLE001 - 调用本身失败也要给出原因
        return ElevationResult(exe=exe, params=params,
                               detail=f"{type(exc).__name__}: {exc}")

    code = int(ctypes.cast(ret, ctypes.c_void_p).value or 0)
    if code > 32:
        return ElevationResult(started=True, code=code, exe=exe, params=params)
    # <= 32 即为错误码；保留原始值便于排查
    return ElevationResult(
        started=False, code=code, exe=exe, params=params,
        detail=describe_shell_error(code),
    )


def request_admin_restart(extra_args: list[str] | None = None) -> bool:
    """用 UAC 提权重新启动当前程序。

    返回 True 表示提权请求已发出（用户点了「是」），
    调用方应随后退出自身进程。需要知道失败原因时用
    :func:`request_admin_restart_detailed`。
    """
    return request_admin_restart_detailed(extra_args).started


# ==========================================================================
# 进程枚举
# ==========================================================================
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),  # ULONG_PTR
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


@dataclass
class ProcessInfo:
    pid: int
    name: str
    path: str = ""

    @property
    def display(self) -> str:
        return f"{self.name} (PID {self.pid})"


def query_process_path(pid: int) -> str:
    """取进程完整可执行文件路径；无权访问时返回空串。"""
    if not IS_WINDOWS:
        return ""
    kernel32 = _dll("kernel32")
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        kernel32.CloseHandle(handle)


def iter_processes() -> list[ProcessInfo]:
    """枚举全部进程（只有名字，不含路径，速度快）。"""
    if not IS_WINDOWS:
        return []
    kernel32 = _dll("kernel32")
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = (ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W))
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = (ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W))
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        return []

    result: list[ProcessInfo] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            result.append(ProcessInfo(entry.th32ProcessID, entry.szExeFile))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def find_dst_processes() -> list[ProcessInfo]:
    """找出所有饥荒联机版相关进程（带完整路径）。"""
    hints = tuple(h.lower() for h in config.DST_PROCESS_HINTS)
    matched: list[ProcessInfo] = []

    for proc in iter_processes():
        name_l = (proc.name or "").lower()
        if any(h in name_l for h in hints):
            proc.path = query_process_path(proc.pid)
            matched.append(proc)
            continue
        # 进程名不匹配时再看路径（例如某些发行版 exe 名不带 dontstarve）
        path = query_process_path(proc.pid)
        if path and any(h in path.lower() for h in hints):
            proc.path = path
            matched.append(proc)

    return matched


# ==========================================================================
# UDP 端点表
# ==========================================================================
class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class _UDP_TABLE_HEADER(ctypes.Structure):
    _fields_ = [("dwNumEntries", wintypes.DWORD)]


@dataclass
class UdpEndpoint:
    address: str
    port: int
    pid: int


def get_udp_endpoints() -> list[UdpEndpoint]:
    """读取系统 UDP 端点表（IPv4）。

    这是本工具的关键信息来源：直接问系统「饥荒进程到底监听哪个端口」，
    比去解析游戏配置文件可靠得多。
    """
    if not IS_WINDOWS:
        return []

    iphlpapi = _dll("iphlpapi")
    iphlpapi.GetExtendedUdpTable.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_int,
        wintypes.DWORD,
    )
    iphlpapi.GetExtendedUdpTable.restype = wintypes.DWORD

    size = wintypes.DWORD(0)
    # 第一次调用只为了取所需缓冲区大小，必然返回 ERROR_INSUFFICIENT_BUFFER
    iphlpapi.GetExtendedUdpTable(
        None, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0
    )
    if size.value <= 0:
        return []

    buf = ctypes.create_string_buffer(size.value)
    ret = iphlpapi.GetExtendedUdpTable(
        buf, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0
    )
    if ret != 0:
        return []

    header = ctypes.cast(buf, ctypes.POINTER(_UDP_TABLE_HEADER)).contents
    count = header.dwNumEntries
    if count <= 0:
        return []

    row_array = (MIB_UDPROW_OWNER_PID * count).from_buffer(
        buf, ctypes.sizeof(wintypes.DWORD)
    )

    endpoints: list[UdpEndpoint] = []
    for row in row_array:
        # 表内为网络字节序：地址按小端读入后 pack('<I') 还原，端口做 ntohs
        addr = socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr))
        port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        endpoints.append(UdpEndpoint(addr, port, row.dwOwningPid))
    return endpoints


def get_dst_listen_ports(dst_pids: set[int]) -> list[int]:
    """从 UDP 表中挑出饥荒进程的「服务器监听端口」。

    判别依据：服务器监听套接字绑定在 0.0.0.0（所有网卡），
    且端口不在系统动态端口段内。客户端自己的临时套接字会被排除掉。
    """
    if not dst_pids:
        return []
    ports: set[int] = set()
    for ep in get_udp_endpoints():
        if ep.pid not in dst_pids:
            continue
        if ep.address != "0.0.0.0":
            continue
        if ep.port <= 0 or ep.port >= config.EPHEMERAL_PORT_START:
            continue
        ports.add(ep.port)
    return sorted(ports)


# ==========================================================================
# 本机 IPv4 地址
# ==========================================================================
class MIB_IPADDRROW(ctypes.Structure):
    _fields_ = [
        ("dwAddr", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("dwMask", wintypes.DWORD),
        ("dwBCastAddr", wintypes.DWORD),
        ("dwReasmSize", wintypes.DWORD),
        ("unused1", wintypes.WORD),
        ("wType", wintypes.WORD),
    ]


def get_local_ipv4_addresses() -> list[str]:
    """枚举本机所有 IPv4 地址（已过滤回环与 169.254 自动分配地址）。"""
    if not IS_WINDOWS:
        return []
    try:
        iphlpapi = _dll("iphlpapi")
        iphlpapi.GetIpAddrTable.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.BOOL,
        )
        iphlpapi.GetIpAddrTable.restype = wintypes.DWORD

        size = wintypes.ULONG(0)
        iphlpapi.GetIpAddrTable(None, ctypes.byref(size), False)
        if size.value <= 0:
            return []

        buf = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), False) != 0:
            return []

        count = ctypes.cast(buf, ctypes.POINTER(_UDP_TABLE_HEADER)).contents.dwNumEntries
        if count <= 0:
            return []

        rows = (MIB_IPADDRROW * count).from_buffer(buf, ctypes.sizeof(wintypes.ULONG))
        addresses: list[str] = []
        for row in rows:
            addr = socket.inet_ntoa(struct.pack("<I", row.dwAddr))
            if addr.startswith("127.") or addr.startswith("169.254."):
                continue
            if addr not in addresses:
                addresses.append(addr)
        return addresses
    except Exception:
        return []


def get_primary_local_ip() -> str:
    """取默认出口网卡的本机 IP（不实际发包，只让系统选路）。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("223.5.5.5", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        return ""


# ==========================================================================
# 剪贴板
# ==========================================================================
def set_clipboard_text(text: str) -> bool:
    """写入 Windows 剪贴板（CF_UNICODETEXT）。"""
    if not IS_WINDOWS:
        return False

    user32 = _dll("user32")
    kernel32 = _dll("kernel32")

    kernel32.GlobalAlloc.argtypes = (wintypes.UINT, ctypes.c_size_t)
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = (wintypes.HGLOBAL,)
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = (wintypes.HGLOBAL,)
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = (wintypes.HGLOBAL,)
    kernel32.GlobalFree.restype = wintypes.HGLOBAL

    user32.OpenClipboard.argtypes = (wintypes.HWND,)
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = (wintypes.UINT, wintypes.HANDLE)
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.CloseClipboard.restype = wintypes.BOOL

    payload = (text + "\0").encode("utf-16-le")
    handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(payload))
    if not handle:
        return False

    locked = kernel32.GlobalLock(handle)
    if not locked:
        kernel32.GlobalFree(handle)
        return False
    ctypes.memmove(locked, payload, len(payload))
    kernel32.GlobalUnlock(handle)

    # 剪贴板常被别的程序短暂占用，重试几次
    opened = False
    for _ in range(10):
        if user32.OpenClipboard(None):
            opened = True
            break
        time.sleep(0.05)
    if not opened:
        kernel32.GlobalFree(handle)
        return False

    try:
        user32.EmptyClipboard()
        if not user32.SetClipboardData(CF_UNICODETEXT, handle):
            kernel32.GlobalFree(handle)
            return False
        # 成功后内存所有权归系统，不能再 GlobalFree
        return True
    finally:
        user32.CloseClipboard()


def get_clipboard_text() -> str:
    """读取 Windows 剪贴板里的文本（CF_UNICODETEXT）；没有文本时返回空串。"""
    if not IS_WINDOWS:
        return ""

    user32 = _dll("user32")
    kernel32 = _dll("kernel32")

    user32.OpenClipboard.argtypes = (wintypes.HWND,)
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = (wintypes.UINT,)
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.IsClipboardFormatAvailable.argtypes = (wintypes.UINT,)
    user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    kernel32.GlobalLock.argtypes = (wintypes.HGLOBAL,)
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = (wintypes.HGLOBAL,)
    kernel32.GlobalUnlock.restype = wintypes.BOOL

    for _ in range(10):
        if user32.OpenClipboard(None):
            break
        time.sleep(0.05)
    else:
        return ""

    try:
        if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return ""
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""
        locked = kernel32.GlobalLock(handle)
        if not locked:
            return ""
        try:
            # 内容以 \0 结尾的 UTF-16；剪贴板里可能带多余尾零，去掉
            return ctypes.wstring_at(locked).rstrip("\x00")
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


# ==========================================================================
# 高 DPI
# ==========================================================================
def enable_dpi_awareness() -> float:
    """开启 DPI 感知，避免界面发虚；返回系统缩放比（1.0 = 100%）。"""
    if not IS_WINDOWS:
        return 1.0

    dpi = 96
    try:
        user32 = _dll("user32")
        user32.GetDC.argtypes = (wintypes.HWND,)
        user32.GetDC.restype = wintypes.HDC
        user32.ReleaseDC.argtypes = (wintypes.HWND, wintypes.HDC)
        user32.ReleaseDC.restype = ctypes.c_int
        try:
            # Windows 10 1607+ ：SYSTEM_DPI_AWARE
            _dll("shcore").SetProcessDpiAwareness(1)
        except Exception:
            user32.SetProcessDPIAware()

        # 取主显示器 DPI
        hdc = user32.GetDC(None)
        if hdc:
            gdi32 = _dll("gdi32")
            gdi32.GetDeviceCaps.argtypes = (wintypes.HDC, ctypes.c_int)
            gdi32.GetDeviceCaps.restype = ctypes.c_int
            dpi = int(gdi32.GetDeviceCaps(hdc, 88))  # LOGPIXELSX = 88
            user32.ReleaseDC(None, hdc)
    except Exception:
        pass

    if dpi <= 0:
        dpi = 96
    return dpi / 96.0
