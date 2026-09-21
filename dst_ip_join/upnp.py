# -*- coding: utf-8 -*-
"""纯标准库实现的 UPnP IGD 客户端（自动端口映射）。

流程：
  1. SSDP（UDP 多播 239.255.255.250:1900）M-SEARCH 找网关
  2. 拉取设备描述 XML，定位 WANIPConnection / WANPPPConnection 服务
  3. 对该服务的 controlURL 发 SOAP 请求做 AddPortMapping 等操作

为什么自己写而不用 miniupnpc：本机 pip 环境要求必须在 venv 中安装，
而这个工具希望做到「零依赖、拷走就能跑」，所以整条链路都用标准库实现。
"""

from __future__ import annotations

import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from xml.sax.saxutils import escape as xml_escape

from . import config

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

SSDP_SEARCH_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "upnp:rootdevice",
)

_USER_AGENT = f"{config.APP_ID}/{config.APP_VERSION} UPnP/1.1"

# 国内光猫/路由器常见的 IGD 描述文件位置。
# 很多设备不支持单播 M-SEARCH，直接猜路径反而更快（实测 ZTE 在 :52869/gatedesc.xml）。
IGD_DESCRIPTION_PATHS = (
    (52869, "/gatedesc.xml"),
    (80, "/gatedesc.xml"),
    (80, "/rootDesc.xml"),
    (52869, "/rootDesc.xml"),
    (80, "/upnp/IGD.xml"),
    (8080, "/gatedesc.xml"),
    (1900, "/gatedesc.xml"),
)


def candidate_description_urls(host: str, open_ports: set[int]) -> list[str]:
    """根据已探测到的开放端口，列出值得一试的描述文件 URL。"""
    urls: list[str] = []
    for port, path in IGD_DESCRIPTION_PATHS:
        if port not in open_ports:
            continue
        url = f"http://{host}:{port}{path}"
        if url not in urls:
            urls.append(url)
    return urls

# UPnP 控制点必须直连局域网设备，绝不能走代理
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

UPNP_ERROR_NAMES = {
    401: "无效操作",
    402: "参数无效",
    501: "操作失败",
    606: "操作不被允许",
    714: "没有这个端口映射条目",
    715: "不支持通配符外部端口",
    716: "不支持内部端口通配符",
    718: "端口映射冲突（该外部端口已被占用）",
    724: "同一客户端已有相同协议映射",
    725: "路由器只支持永久租约",
    726: "不支持远程主机通配符",
    727: "外部端口不适合做通配符",
    728: "不支持内部客户端通配符",
    729: "冲突：不同内部客户端使用了相同外部端口",
    732: "不允许映射通配符端口",
}


class SoapError(Exception):
    """UPnP 设备返回的 SOAP 错误。"""

    def __init__(self, code: int, message: str = "", raw: bytes = b""):
        self.code = code
        self.message = message or UPNP_ERROR_NAMES.get(code, "")
        self.raw = raw
        super().__init__(f"UPnP 错误 {code}：{self.message}")


# ==========================================================================
# XML / HTTP 小工具
# ==========================================================================
def _strip_namespaces(root: ET.Element) -> ET.Element:
    """剥掉 XML 命名空间，后续用纯标签名查找，避免前缀差异带来的麻烦。"""
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
        for key in list(element.attrib):
            if "}" in key:
                element.attrib[key.split("}", 1)[1]] = element.attrib.pop(key)
    return root


def _text(element: ET.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    return element.text.strip()


def _http_get_bytes(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "text/xml, application/xml, */*",
            "Connection": "close",
        },
    )
    with _OPENER.open(request, timeout=timeout) as response:
        return response.read()


# ==========================================================================
# SSDP 发现
# ==========================================================================
def _parse_http_headers(data: bytes) -> dict[str, str]:
    text = data.decode("latin-1", "replace")
    headers: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def ssdp_discover(
    timeout: float | None = None,
    log=None,
    unicast_targets: list[str] | None = None,
    exclude_hosts: tuple[str, ...] = (),
) -> list[str]:
    """发 SSDP M-SEARCH，返回所有响应里的 LOCATION 地址。

    :param unicast_targets: 除了多播，再直接向这些 IP 发单播 M-SEARCH。
        多播不跨网段，双重 NAT 场景下探测上一级光猫只能靠单播。
    :param exclude_hosts: 忽略来自这些主机的响应。探测上游时必须排除已知的
        本机路由器，否则多播响应会把上一级的探测结果搅掉。
    """
    timeout = timeout if timeout is not None else config.SSDP_DISCOVER_TIMEOUT
    locations: list[str] = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return []

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except OSError:
            pass
        sock.settimeout(0.4)
        try:
            sock.bind(("", 0))
        except OSError:
            return []

        def _m_search(target: str) -> bytes:
            message = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                f"ST: {target}\r\n"
                f"USER-AGENT: {_USER_AGENT}\r\n"
                "\r\n"
            )
            return message.encode("ascii")

        for target in SSDP_SEARCH_TARGETS:
            try:
                sock.sendto(_m_search(target), (SSDP_ADDR, SSDP_PORT))
            except OSError:
                continue

        # 单播探测：只需两种 ST，发太多会让老旧光猫来不及回应
        unicast_sts = (
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "upnp:rootdevice",
        )
        for ip in unicast_targets or ():
            for target in unicast_sts:
                try:
                    sock.sendto(_m_search(target), (ip, SSDP_PORT))
                except OSError:
                    continue

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(65507)
            except socket.timeout:
                continue
            except OSError:
                break
            location = _parse_http_headers(data).get("location", "")
            if not location or location in locations:
                continue
            if urllib.parse.urlsplit(location).hostname in exclude_hosts:
                continue
            locations.append(location)
            if log:
                log(f"    发现 UPnP 设备：{location}（来自 {addr[0]}）")
    finally:
        sock.close()

    return locations


# ==========================================================================
# 网关服务定位
# ==========================================================================
@dataclass
class Gateway:
    location: str
    service_type: str
    control_url: str
    friendly_name: str = ""
    manufacturer: str = ""
    model: str = ""

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.location).hostname or ""

    @property
    def display(self) -> str:
        parts = [p for p in (self.friendly_name, self.manufacturer, self.model) if p]
        name = " ".join(parts) if parts else "未知型号"
        return f"{self.host} - {name}"

    # ---------------------------------------------------------------- SOAP
    def _call(self, action: str, args: dict[str, object]) -> dict[str, str]:
        inner = "".join(
            f"<{key}>{xml_escape(str(value))}</{key}>" for key, value in args.items()
        )
        envelope = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:{action} xmlns:u="{self.service_type}">'
            f"{inner}"
            f"</u:{action}></s:Body></s:Envelope>"
        )

        request = urllib.request.Request(
            self.control_url,
            data=envelope.encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{self.service_type}#{action}"',
                "User-Agent": _USER_AGENT,
                "Connection": "close",
            },
        )

        try:
            with _OPENER.open(request, timeout=config.UPNP_SOAP_TIMEOUT) as response:
                return _parse_soap_response(response.read(), action)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            raise SoapError(_extract_error_code(raw), raw=raw) from exc

    # ------------------------------------------------------------- 高阶层
    def external_ip(self) -> str:
        result = self._call("GetExternalIPAddress", {})
        return result.get("NewExternalIPAddress", "")

    def add_mapping(
        self,
        external_port: int,
        protocol: str,
        internal_port: int,
        internal_client: str,
        description: str,
        lease: int = 0,
    ) -> tuple[bool, str]:
        """添加端口映射。返回 (是否成功, 说明)。"""
        args = {
            "NewRemoteHost": "",
            "NewExternalPort": external_port,
            "NewProtocol": protocol.upper(),
            "NewInternalPort": internal_port,
            "NewInternalClient": internal_client,
            "NewEnabled": "1",
            "NewPortMappingDescription": description,
            "NewLeaseDuration": lease,
        }

        for attempt in range(2):
            try:
                self._call("AddPortMapping", args)
                return True, f"已映射 UDP {external_port}"
            except SoapError as exc:
                if exc.code == 725 and args["NewLeaseDuration"] != 0:
                    # 路由器只支持永久租约，改成 0 重试
                    args["NewLeaseDuration"] = 0
                    continue
                if exc.code == 718:
                    return self._resolve_conflict(
                        external_port, protocol, internal_port, internal_client
                    )
                return False, f"映射 UDP {external_port} 失败：{exc.message}"
            except Exception as exc:  # noqa: BLE001
                return False, f"映射 UDP {external_port} 出错：{exc}"

        return False, f"映射 UDP {external_port} 失败：路由器拒绝了租约设置"

    def _resolve_conflict(
        self,
        external_port: int,
        protocol: str,
        internal_port: int,
        internal_client: str,
    ) -> tuple[bool, str]:
        """718 冲突：看看已有映射是不是正好就是我们要的。"""
        try:
            existing = self.get_mapping(external_port, protocol)
        except SoapError as exc:
            return False, f"UDP {external_port} 已被占用，且无法读取占用详情：{exc.message}"

        if not existing:
            return False, f"UDP {external_port} 已被占用，且无法读取占用详情"

        same_client = existing.get("NewInternalClient", "") == internal_client
        same_port = str(existing.get("NewInternalPort", "")) == str(internal_port)
        if same_client and same_port:
            return True, f"UDP {external_port} 已有可用映射"

        owner = existing.get("NewInternalClient") or "另一台设备"
        return False, f"UDP {external_port} 被 {owner} 占用（不是本机）"

    def get_mapping(self, external_port: int, protocol: str) -> dict[str, str] | None:
        """查询某个外部端口的映射详情；不存在时返回 None。"""
        try:
            return self._call(
                "GetSpecificPortMappingEntry",
                {
                    "NewRemoteHost": "",
                    "NewExternalPort": external_port,
                    "NewProtocol": protocol.upper(),
                },
            )
        except SoapError as exc:
            if exc.code == 714:
                return None
            raise

    def delete_mapping(self, external_port: int, protocol: str) -> tuple[bool, str]:
        try:
            self._call(
                "DeletePortMapping",
                {
                    "NewRemoteHost": "",
                    "NewExternalPort": external_port,
                    "NewProtocol": protocol.upper(),
                },
            )
            return True, f"已移除 UDP {external_port} 映射"
        except SoapError as exc:
            if exc.code == 714:
                return True, f"UDP {external_port} 映射本就不存在"
            return False, f"移除 UDP {external_port} 映射失败：{exc.message}"
        except Exception as exc:  # noqa: BLE001
            return False, f"移除 UDP {external_port} 映射出错：{exc}"


_UPNP_ERROR_CODE_RE = re.compile(r"<errorCode>\s*(\d+)\s*</errorCode>", re.IGNORECASE)


def _extract_error_code(raw: bytes) -> int:
    text = raw.decode("utf-8", "replace")
    match = _UPNP_ERROR_CODE_RE.search(text)
    if match:
        return int(match.group(1))
    return -1


def _parse_soap_response(raw: bytes, action: str) -> dict[str, str]:
    try:
        root = _strip_namespaces(ET.fromstring(raw))
    except ET.ParseError:
        return {}

    result: dict[str, str] = {}
    for element in root.iter():
        if element.tag == f"{action}Response" or element.tag.endswith("Response"):
            for child in element:
                result[child.tag] = _text(child)
    if not result:
        # 有些设备层级更深，兜底再扫一遍
        for element in root.iter():
            if element.tag.startswith("New"):
                result[element.tag] = _text(element)
    return result


def discover_gateway(
    timeout: float | None = None,
    log=None,
    unicast_targets: list[str] | None = None,
    prefer_host: str = "",
    exclude_hosts: tuple[str, ...] = (),
    extra_locations: tuple[str, ...] = (),
    description_timeout: float | None = None,
) -> Gateway | None:
    """找一台支持端口映射的网关。

    :param unicast_targets: 额外单播探测的 IP（双重 NAT 时用来找上一级光猫）。
    :param prefer_host: 排序时优先返回该主机的网关。
    :param exclude_hosts: 忽略这些主机上报的 SSDP 响应。
    :param extra_locations: 额外尝试的设备描述 URL（跳过 SSDP 直接猜路径）。
    :param description_timeout: 拉取描述 XML 的超时；猜路径时应该给得很短。
    """
    locations = ssdp_discover(
        timeout=timeout,
        log=log,
        unicast_targets=unicast_targets,
        exclude_hosts=exclude_hosts,
    )

    for url in extra_locations:
        if url not in locations:
            locations.append(url)

    if not locations:
        if log:
            log("    未收到任何 SSDP 响应（设备可能关闭了 UPnP）")
        return None

    candidates: list[Gateway] = []
    fetched = 0
    fetch_timeout = description_timeout or config.HTTP_TIMEOUT
    for location in locations:
        try:
            raw = _http_get_bytes(location, fetch_timeout)
            root = _strip_namespaces(ET.fromstring(raw))
        except Exception as exc:  # noqa: BLE001
            if log:
                log(f"    读取设备描述失败 {location}：{exc}")
            continue
        fetched += 1

        url_base = _text(root.find(".//URLBase")) or location
        friendly = _text(root.find(".//friendlyName"))
        manufacturer = _text(root.find(".//manufacturer"))
        model = _text(root.find(".//modelName"))

        for service in root.iter("service"):
            service_type = _text(service.find("serviceType"))
            if "WANIPConnection" not in service_type and "WANPPPConnection" not in service_type:
                continue
            control_url = _text(service.find("controlURL"))
            if not control_url:
                continue

            candidates.append(
                Gateway(
                    location=location,
                    service_type=service_type,
                    control_url=urllib.parse.urljoin(url_base, control_url),
                    friendly_name=friendly,
                    manufacturer=manufacturer,
                    model=model,
                )
            )

    if not candidates:
        if log:
            if fetched == 0:
                log("    没有可用的设备描述（设备可能未开启 UPnP）")
            else:
                log("    能取到设备描述，但没有提供端口映射服务（WANIPConnection）")
        return None

    # 排序：优先指定主机 > WANIPConnection > 其他
    def _rank(gw: Gateway) -> tuple[int, int]:
        host_bonus = 0 if (prefer_host and gw.host == prefer_host) else 1
        service_bonus = 0 if "WANIPConnection" in gw.service_type else 1
        return (host_bonus, service_bonus)

    candidates.sort(key=_rank)
    gateway = candidates[0]
    if log:
        log(f"    可控网关：{gateway.display}")
    return gateway
