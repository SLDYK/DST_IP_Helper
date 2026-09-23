# -*- coding: utf-8 -*-
"""检测编排：把各模块串起来跑一遍，给出结论和可分享的地址。

这里是工具的「大脑」，核心是分清三个完全不同的地址：

  * ``router_wan_ip``   路由器 / 光猫自报的 WAN 口地址。它可能是私有地址
                        （说明是双重 NAT），也可能落在 100.64/10 里
                        （运营商级 NAT）。
  * ``public_ip``       HTTP 接口 / STUN 拿到的**真实出口地址**，
                        这才是能发给朋友的地址。
  * ``primary_local_ip`` 局域网地址，同一个 WiFi 下的朋友用这个。

国内家庭网络最常见也最容易被误判的情况是「光猫 + 路由器」两级 NAT：

    电脑 192.168.1.100 → 路由器 192.168.1.1 → 光猫 192.168.0.1 → 公网

只在路由器上做端口映射是白忙活，包到了光猫就被丢掉。所以本工具检测到
双层 NAT 后，会单播 SSDP 主动把上一级设备找出来并补上映射。
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from . import config, firewall, netinfo, upnp, winproc

LEVEL_OK = "ok"
LEVEL_WARN = "warn"
LEVEL_FAIL = "fail"
LEVEL_INFO = "info"


@dataclass
class CheckItem:
    level: str
    title: str
    detail: str = ""


@dataclass
class Report:
    # 环境
    is_admin: bool = False
    # 饥荒进程
    dst_running: bool = False
    dst_processes: list[str] = field(default_factory=list)
    # 端口
    detected_ports: list[int] = field(default_factory=list)
    target_ports: list[int] = field(default_factory=list)
    master_port: int = config.DEFAULT_MASTER_PORT
    # 地址
    local_ips: list[str] = field(default_factory=list)
    primary_local_ip: str = ""
    public_ip: str = ""
    public_ip_source: str = ""
    public_ip_via_proxy: bool = False
    # NAT
    nat: netinfo.NatInfo = field(default_factory=netinfo.NatInfo)
    nat_present: bool = False
    cgnat: bool = False
    # 路由器层
    gateway_name: str = ""
    gateway_host: str = ""
    router_wan_ip: str = ""
    router_mapped: list[int] = field(default_factory=list)
    router_failed: list[int] = field(default_factory=list)
    # 上游（光猫）层
    double_nat: bool = False
    upstream_gateway_name: str = ""
    upstream_mapped: list[int] = field(default_factory=list)
    # 防火墙
    firewall_allowed: list[int] = field(default_factory=list)
    firewall_failed: list[int] = field(default_factory=list)
    # 结论
    checks: list[CheckItem] = field(default_factory=list)
    level: str = LEVEL_INFO
    headline: str = ""
    primary_address: str = ""
    lan_address: str = ""
    advice: list[str] = field(default_factory=list)
    share_text: str = ""

    @property
    def shareable_ip(self) -> str:
        """真正可以发给朋友直连的公网地址。

        依次尝试 HTTP 查询结果 → STUN 观测结果 → 路由器自报 WAN 地址，
        只接受被判定为 public 的那一个。
        """
        for candidate in (self.public_ip, self.nat.mapped_ip, self.router_wan_ip):
            if candidate and netinfo.classify_ip(candidate) == "public":
                return candidate
        return ""

    @property
    def connect_command(self) -> str:
        """饥荒控制台的直连指令，形如 ``c_connect("1.2.3.4", 10999)``。

        这就是「复制指令」按钮写进剪贴板的东西：朋友按 ` 打开控制台、粘贴回车
        即可加入，比在「浏览游戏」里填 IP:端口 可靠得多。

        没有公网地址时退回局域网地址，同一个 WiFi 下的朋友同样能用。
        """
        address = self.primary_address or self.lan_address
        if not address:
            return ""
        ip, _, port = address.rpartition(":")
        if not ip:
            ip, port = address, str(self.master_port)
        return config.join_command(ip, port)

    @property
    def all_ports_mapped(self) -> bool:
        """需要的端口在每一层 NAT 上都映射成功了（只有一层时只看那一层）。"""
        if not self.target_ports:
            return False
        if not set(self.target_ports) <= set(self.router_mapped):
            return False
        if not self.double_nat:
            return True
        return set(self.target_ports) <= set(self.upstream_mapped)


class Reporter:
    """把检测过程中的日志与状态变化推给界面。"""

    def __init__(self, log=None, status=None):
        self._log_cb = log
        self._status_cb = status
        self.items: list[CheckItem] = []

    def log(self, message: str) -> None:
        if self._log_cb:
            self._log_cb(message)

    def section(self, title: str) -> None:
        self.log("")
        self.log(f"== {title} ==")

    def status(self, level: str, title: str, detail: str = "") -> None:
        item = CheckItem(level, title, detail)
        self.items.append(item)
        self.log(f"[{level.upper():4}] {title}" + (f" — {detail}" if detail else ""))
        if self._status_cb:
            self._status_cb(item)


# ==========================================================================
# 主流程
# ==========================================================================
def run_diagnosis(
    ports: list[int] | None = None,
    log=None,
    status=None,
    configure: bool = True,
) -> Report:
    """跑完整套检测与配置。

    :param ports: 手动指定端口；为 None 时自动从系统 UDP 表读取。
    :param configure: 是否真的去写 UPnP 映射和防火墙规则。
    """
    reporter = Reporter(log, status)
    report = Report()
    report.is_admin = winproc.is_admin()

    _step_environment(report, reporter)
    _step_dst_process(report, reporter)
    _step_ports(report, reporter, ports)
    _step_local_address(report, reporter)
    _step_public_ip(report, reporter)
    _step_nat(report, reporter)
    _step_upnp(report, reporter, configure)
    _step_firewall(report, reporter, configure)

    report.checks = reporter.items
    _build_conclusion(report)

    reporter.section("结论")
    reporter.log(f"    {report.headline}")
    for line in report.advice:
        reporter.log(f"    · {line}")
    return report


# --------------------------------------------------------------------------
# 各步骤
# --------------------------------------------------------------------------
def _step_environment(report: Report, reporter: Reporter) -> None:
    reporter.section("环境检查")
    reporter.status(
        LEVEL_OK if report.is_admin else LEVEL_WARN,
        "管理员权限",
        "已具备，可自动配置防火墙" if report.is_admin else "未提权，防火墙需手动放行",
    )


def _step_dst_process(report: Report, reporter: Reporter) -> None:
    reporter.section("检测饥荒联机版")
    dst_procs = winproc.find_dst_processes()
    report.dst_running = bool(dst_procs)
    report.dst_processes = [p.display for p in dst_procs]

    if dst_procs:
        reporter.status(LEVEL_OK, "饥荒进程", "、".join(report.dst_processes))
    else:
        reporter.status(
            LEVEL_WARN,
            "饥荒进程",
            "没有检测到，将按默认端口配置；请先在 Steam 里开好房间",
        )


def _step_ports(report: Report, reporter: Reporter, ports: list[int] | None) -> None:
    reporter.section("确定监听端口")

    if ports:
        report.detected_ports = list(ports)
    elif report.dst_running:
        pids = {proc.pid for proc in winproc.find_dst_processes()}
        report.detected_ports = winproc.get_dst_listen_ports(pids)

    if report.detected_ports:
        reporter.status(
            LEVEL_OK,
            "世界监听端口",
            "UDP " + "、".join(str(p) for p in report.detected_ports),
        )
    else:
        reporter.status(
            LEVEL_WARN,
            "世界监听端口",
            "未自动识别，改用默认值 UDP "
            + "、".join(str(p) for p in config.DEFAULT_PORTS),
        )

    report.target_ports = report.detected_ports or list(config.DEFAULT_PORTS)
    report.master_port = config.pick_master_port(report.target_ports)


def _step_local_address(report: Report, reporter: Reporter) -> None:
    reporter.section("本机地址")
    report.local_ips = netinfo.get_local_ips()
    report.primary_local_ip = report.local_ips[0] if report.local_ips else ""

    if report.primary_local_ip:
        reporter.status(LEVEL_OK, "本机局域网 IP", "、".join(report.local_ips))
        report.lan_address = f"{report.primary_local_ip}:{report.master_port}"
    else:
        reporter.status(LEVEL_FAIL, "本机局域网 IP", "未能获取本机地址")


def _step_public_ip(report: Report, reporter: Reporter) -> None:
    reporter.section("公网出口 IP")
    (
        report.public_ip,
        report.public_ip_source,
        report.public_ip_via_proxy,
    ) = netinfo.get_public_ip(log=reporter.log)

    if not report.public_ip:
        reporter.status(LEVEL_FAIL, "公网出口 IP", "所有查询接口都不可达")
        return

    kind = netinfo.classify_ip(report.public_ip)
    detail = f"{report.public_ip}（来源 {report.public_ip_source}）"
    if kind == "cgnat":
        reporter.status(LEVEL_FAIL, "公网出口 IP", detail + "，属于运营商级 NAT")
    elif kind == "private":
        reporter.status(LEVEL_FAIL, "公网出口 IP", detail + "，仍是私有地址")
    else:
        reporter.status(LEVEL_OK, "公网出口 IP", detail)


def _step_nat(report: Report, reporter: Reporter) -> None:
    reporter.section("NAT 类型探测")
    report.nat = netinfo.detect_nat(log=reporter.log)

    if not report.nat.available:
        reporter.status(LEVEL_WARN, "NAT 类型", "STUN 全部超时，无法判定")
        return

    if report.nat.endpoint_independent is True:
        level, text = LEVEL_OK, "映射稳定（端口映射会生效）"
    elif report.nat.endpoint_independent is False:
        level, text = LEVEL_WARN, "疑似对称 NAT，外部主动连入较难"
    else:
        level, text = LEVEL_INFO, "信息不足"

    text += f"；STUN 观测出口 {report.nat.mapped_ip}:{report.nat.mapped_port}"
    if report.nat.port_preserved:
        text += "（端口未被改写）"
    reporter.status(level, "NAT 类型", text)


def _step_upnp(report: Report, reporter: Reporter, configure: bool) -> None:
    reporter.section("UPnP 自动端口映射")

    if not configure:
        reporter.status(LEVEL_INFO, "UPnP", "本次未执行配置")
        return

    gateway = upnp.discover_gateway(log=reporter.log)
    if gateway is None:
        reporter.status(
            LEVEL_WARN, "本机路由器", "未发现可用 UPnP 网关，需要手动做端口映射"
        )
        return

    report.gateway_name = gateway.display
    report.gateway_host = gateway.host
    try:
        report.router_wan_ip = gateway.external_ip()
    except Exception:  # noqa: BLE001
        report.router_wan_ip = ""

    detail = report.gateway_name
    if report.router_wan_ip:
        label = {
            "public": "公网地址",
            "private": "私有地址，说明上游还有一层 NAT",
            "cgnat": "运营商级 NAT 地址",
        }.get(netinfo.classify_ip(report.router_wan_ip), "未知")
        detail += f"；WAN 口 {report.router_wan_ip}（{label}）"
    reporter.status(LEVEL_OK, "本机路由器", detail)

    for port in report.target_ports:
        ok, message = gateway.add_mapping(
            external_port=port,
            protocol="UDP",
            internal_port=port,
            internal_client=report.primary_local_ip,
            description=f"{config.UPNP_MAPPING_DESC_PREFIX}-{port}",
        )
        (report.router_mapped if ok else report.router_failed).append(port)
        reporter.log(f"    [路由器] {message}")

    if report.router_mapped:
        reporter.status(
            LEVEL_OK,
            "路由器端口映射",
            "UDP " + "、".join(str(p) for p in report.router_mapped),
        )
    if report.router_failed:
        reporter.status(
            LEVEL_FAIL,
            "路由器端口映射",
            "失败：UDP " + "、".join(str(p) for p in report.router_failed),
        )

    if report.router_wan_ip:
        report.nat_present = report.router_wan_ip not in report.local_ips
        kind = netinfo.classify_ip(report.router_wan_ip)
        report.cgnat = kind == "cgnat"
        if kind == "private":
            _probe_upstream(report, reporter, report.router_wan_ip)


def _step_firewall(report: Report, reporter: Reporter, configure: bool) -> None:
    reporter.section("Windows 防火墙")

    if not configure:
        reporter.status(LEVEL_INFO, "防火墙", "本次未执行配置")
        return
    if not report.is_admin:
        reporter.status(
            LEVEL_WARN,
            "Windows 防火墙",
            "缺少管理员权限，未能自动放行（同一局域网联机不受影响）",
        )
        return

    for port in report.target_ports:
        ok, message = firewall.add_udp_rule(port)
        (report.firewall_allowed if ok else report.firewall_failed).append(port)
        reporter.log(f"    {message}")

    if report.firewall_allowed:
        reporter.status(
            LEVEL_OK,
            "Windows 防火墙",
            "已放行 UDP " + "、".join(str(p) for p in report.firewall_allowed),
        )
    if report.firewall_failed:
        reporter.status(
            LEVEL_FAIL,
            "Windows 防火墙",
            "失败：UDP " + "、".join(str(p) for p in report.firewall_failed),
        )


# ==========================================================================
# 上游 NAT 探测（双重 NAT）
# ==========================================================================
def _probe_upstream(report: Report, reporter: Reporter, router_wan_ip: str) -> None:
    """主路由的 WAN 口是私有地址时，尝试把上一级设备也打通。

    国内家庭网络常见「光猫（路由模式）+ 无线路由器」两级 NAT：

        电脑 192.168.1.100 → 路由器 192.168.1.1 → 光猫 192.168.0.1 → 公网

    只在路由器上映射没用，包到光猫就被丢了。这里单播 SSDP 把光猫找出来，
    再补一条「外部端口 → 路由器 WAN 地址」的映射，两级串起来才通。
    """
    report.double_nat = True

    reporter.section("上游 NAT 探测（双重 NAT）")
    reporter.log(f"    路由器 WAN 口是私有地址 {router_wan_ip}，上游还有一层 NAT")

    candidates = netinfo.upstream_gateway_candidates(router_wan_ip)
    # 关键：必须排除本机路由器，否则它的多播响应又会把自己当成上游网关
    exclude_hosts = (report.gateway_host,) if report.gateway_host else ()

    reachable: list[str] = []
    extra_locations: list[str] = []
    for ip in candidates:
        open_ports = {
            port
            for port in (52869, 80, 8080, 1900)
            if netinfo.tcp_reachable(ip, port, timeout=0.6)
        }
        if open_ports:
            reachable.append(ip)
            reporter.log(f"    {ip} 可达，开放端口 {sorted(open_ports)}")
            # 很多光猫不支持单播 M-SEARCH，按已开放端口直接猜描述文件路径
            extra_locations.extend(upnp.candidate_description_urls(ip, open_ports))
        else:
            reporter.log(f"    {ip} 无响应端口，仍尝试单播 UPnP 探测")

    upstream = upnp.discover_gateway(
        timeout=2.5,
        log=reporter.log,
        unicast_targets=reachable or candidates,
        exclude_hosts=exclude_hosts,
        extra_locations=tuple(extra_locations),
        description_timeout=2.0,
        prefer_host=reachable[0] if reachable else "",
    )
    if upstream is None:
        if reachable:
            detail = (
                "、".join(reachable)
                + " 在线，但没有响应 UPnP（说明 UPnP 已关闭），只能手动配置"
            )
        else:
            detail = (
                "、".join(candidates)
                + " 完全无响应，无法访问上一级设备，只能手动配置"
            )
        reporter.status(LEVEL_WARN, "上游网关", detail)
        return

    report.upstream_gateway_name = upstream.display
    reporter.status(LEVEL_OK, "上游网关", f"{upstream.display}（已找到，可代为映射）")

    for port in report.target_ports:
        ok, message = upstream.add_mapping(
            external_port=port,
            protocol="UDP",
            internal_port=port,
            # 光猫要把包转给「路由器的 WAN 地址」，而不是本机地址
            internal_client=router_wan_ip,
            description=f"{config.UPNP_MAPPING_DESC_PREFIX}-up-{port}",
        )
        if ok:
            report.upstream_mapped.append(port)
        reporter.log(f"    [上游] {message}")

    if report.upstream_mapped:
        reporter.status(
            LEVEL_OK,
            "上游端口映射",
            "UDP " + "、".join(str(p) for p in report.upstream_mapped),
        )
    if len(report.upstream_mapped) < len(report.target_ports):
        missing = [p for p in report.target_ports if p not in report.upstream_mapped]
        reporter.status(
            LEVEL_FAIL,
            "上游端口映射",
            "未打通：UDP " + "、".join(str(p) for p in missing),
        )


# ==========================================================================
# 结论生成
# ==========================================================================
def _build_conclusion(report: Report) -> None:
    public_ip = report.shareable_ip
    if public_ip:
        report.primary_address = f"{public_ip}:{report.master_port}"

    firewall_ok = (
        not report.target_ports
        or bool(report.firewall_allowed)
        or not report.is_admin
    )

    # ---- 完全拿不到公网地址
    if not public_ip:
        report.level = LEVEL_WARN
        report.headline = "拿不到公网 IP，暂时只能局域网联机"
        report.primary_address = report.lan_address
        report.advice = [
            "确认电脑能正常上网；若开了代理 / 加速器，可临时关掉再检测一次",
            f"同一局域网内的朋友可以直接用 {report.lan_address} 加入",
            "跨地区联机需要端口映射或内网穿透",
        ]
        _build_share_text(report)
        return

    # ---- 运营商级 NAT：出口本身不是公网地址，端口映射无解
    if report.cgnat:
        report.level = LEVEL_FAIL
        report.headline = f"检测到运营商级 NAT（{public_ip}），端口映射无法生效"
        report.advice = [
            "打运营商客服申请「公网 IP」，这是唯一能根治的办法",
            "临时方案：内网穿透（playit.gg、frp）或虚拟局域网（ZeroTier、Radmin VPN）",
            f"同一局域网内的朋友可以直接用 {report.lan_address} 加入",
        ]
        _build_share_text(report)
        return

    # ---- 双重 NAT：路由器上面还有一层（通常是光猫）
    if report.double_nat:
        if report.all_ports_mapped:
            report.level = LEVEL_OK
            report.headline = f"已打通两级 NAT，朋友可以直接连接：{report.primary_address}"
            report.advice = [
                "路由器与上游光猫的映射都已自动添加，把上面的地址发给朋友即可",
                "光猫重启后 UPnP 映射可能失效，重跑一次本工具即可",
            ]
        else:
            report.level = LEVEL_WARN
            report.headline = (
                f"检测到双重 NAT（路由器上层还有一层），还差一步：{report.primary_address}"
            )
            upstream_name = report.upstream_gateway_name or "光猫"
            report.advice = [
                f"本机路由器的映射已加好，但上游设备（{upstream_name}）没打通",
                f"登录光猫后台（一般是 192.168.1.1），把 UDP {report.master_port}"
                f" 映射到 {report.router_wan_ip}",
                f"更省事：在光猫上把 DMZ 主机设为 {report.router_wan_ip}，"
                "之后本工具加的路由器映射就能一路通到公网",
                "最优解：把光猫改成桥接、由本机路由器 PPPoE 拨号，只剩一层 NAT",
                f"同一局域网内的朋友可以直接用 {report.lan_address} 加入",
            ]
        if not firewall_ok:
            report.advice.append("另外防火墙未放行，请以管理员身份重启本工具")
        _build_share_text(report)
        return

    # ---- 本机直接持有公网 IP，不存在 NAT
    if report.router_wan_ip and report.router_wan_ip in report.local_ips:
        report.level = LEVEL_OK if firewall_ok else LEVEL_WARN
        report.headline = f"本机直接持有公网 IP，可直连：{report.primary_address}"
        report.advice = (
            ["把上面的地址发给朋友即可"]
            if firewall_ok
            else ["防火墙未放行，请以管理员身份重启本工具"]
        )
        _build_share_text(report)
        return

    # ---- 单层 NAT：看端口映射结果
    if report.all_ports_mapped:
        report.level = LEVEL_OK
        report.headline = f"已自动配置完成，朋友可直接连接：{report.primary_address}"
        report.advice = ["把上面的地址发给朋友即可"]
    elif report.gateway_name:
        report.level = LEVEL_WARN
        report.headline = (
            f"路由器支持 UPnP 但映射失败，需要手动映射 UDP {report.master_port}："
            f"{report.primary_address}"
        )
        host = report.gateway_name.split(" - ")[0]
        report.advice = [
            f"登录路由器后台（{host}），把 UDP {report.master_port} "
            f"映射到 {report.primary_local_ip}",
            "部分路由器需要先在设置里打开「UPnP」开关再重试",
        ]
    else:
        report.level = LEVEL_WARN
        report.headline = f"路由器不支持 UPnP，需要手动端口映射：{report.primary_address}"
        report.advice = [
            f"登录路由器后台，把 UDP {report.master_port}（开了洞穴再加 "
            f"{config.DEFAULT_CAVES_PORT}）映射到本机 {report.primary_local_ip}",
            "如果家里是光猫 + 路由器两级，需要在光猫上也做一次映射（或设 DMZ）",
            "实在不行就用内网穿透或虚拟局域网",
        ]

    if not firewall_ok:
        report.advice.append("另外防火墙未放行，请以管理员身份重启本工具")

    _build_share_text(report)


def _build_share_text(report: Report) -> None:
    timestamp = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    address = report.primary_address or report.lan_address
    ip, _, port = address.rpartition(":")
    if not ip:
        ip, port = address, str(report.master_port)
    command = report.connect_command or config.join_command(ip, port)

    lines = [
        "====== 饥荒联机版 直连信息 ======",
        f"服务器地址：{address}",
        f"（需要分开填的话 → IP：{ip}   端口：{port}）",
        "",
        "【加入方法】",
        "1. 打开饥荒联机版，进入「加入游戏」界面",
        f"2. 在服务器列表的搜索框里输入 {address} 后回车",
        "",
        f"3. 备用（更可靠）：主菜单按 ` 键打开控制台，粘贴 {command} 后回车",
        "",
        f"【网络状态】{report.headline}",
    ]

    if report.lan_address and report.lan_address != address:
        lines.append(f"【同一局域网】可用 {report.lan_address}")

    if report.level == LEVEL_WARN and report.advice:
        lines.append("")
        lines.append("【房主需注意】" + report.advice[0])

    lines.append(f"【生成时间】{timestamp}")
    lines.append("================================")
    report.share_text = "\n".join(lines)


# ==========================================================================
# 撤销配置
# ==========================================================================
def cleanup(ports: list[int] | None = None, log=None, status=None) -> list[str]:
    """删掉本工具添加的防火墙规则和 UPnP 映射（两层都清）。"""
    reporter = Reporter(log, status)
    messages: list[str] = []
    target_ports = list(ports or config.DEFAULT_PORTS)
    scan_ports = sorted(set(target_ports) | set(config.DEFAULT_PORTS))

    reporter.section("撤销本工具的配置")

    if not winproc.is_admin():
        messages.append("防火墙规则需要管理员权限才能删除")
        reporter.log("    未提权，跳过防火墙规则清理")
    else:
        for port in target_ports:
            _ok, message = firewall.remove_udp_rule(port)
            messages.append(message)
            reporter.log(f"    {message}")

    gateway = upnp.discover_gateway(log=reporter.log)
    if gateway is None:
        messages.append("未发现 UPnP 网关，跳过映射清理")
        return messages

    # 上游光猫要先知道本机路由器的 WAN 地址才能定位
    try:
        wan_ip = gateway.external_ip()
    except Exception:  # noqa: BLE001
        wan_ip = ""

    _purge_mappings(gateway, scan_ports, messages, reporter)

    if wan_ip and netinfo.classify_ip(wan_ip) == "private":
        targets = netinfo.upstream_gateway_candidates(wan_ip)
        upstream = upnp.discover_gateway(
            timeout=2.5,
            log=reporter.log,
            unicast_targets=targets,
            exclude_hosts=(gateway.host,) if gateway.host else (),
        )
        if upstream is not None:
            _purge_mappings(upstream, scan_ports, messages, reporter, label="上游")

    return messages


def _purge_mappings(
    gateway: upnp.Gateway | None,
    ports: list[int],
    messages: list[str],
    reporter: Reporter,
    label: str = "路由器",
) -> None:
    """只删本工具建的映射（靠描述前缀识别），绝不碰别人的条目。"""
    if gateway is None:
        return
    for port in ports:
        try:
            existing = gateway.get_mapping(port, "UDP")
        except Exception:  # noqa: BLE001
            continue
        if not existing:
            continue
        description = existing.get("NewPortMappingDescription", "")
        if not description.startswith(config.UPNP_MAPPING_DESC_PREFIX):
            continue
        _ok, message = gateway.delete_mapping(port, "UDP")
        messages.append(f"{label}：{message}")
        reporter.log(f"    [{label}] {message}")
