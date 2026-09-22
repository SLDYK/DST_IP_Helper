# -*- coding: utf-8 -*-
"""全局配置与常量。

本项目刻意只依赖 Python 标准库，不引入任何第三方包，
这样在受限的 pip 环境（require-virtualenv / 无外网）下也能直接跑。
"""

APP_NAME = "饥荒联机版 IP 联机助手"
APP_ID = "dst-ip-join"
APP_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# 饥荒联机版进程识别
# --------------------------------------------------------------------------
# 不同版本 / 平台的可执行文件名可能不同（dontstarve_steam.exe、
# dontstarve_steam_x64.exe、dontstarve_steam_openbeta.exe ...），
# 所以这里用「不区分大小写的子串」匹配进程名与完整路径，避免写死。
DST_PROCESS_HINTS = (
    "dontstarve",
    "don't starve together",
    "dont starve together",
)

# --------------------------------------------------------------------------
# 端口
# --------------------------------------------------------------------------
# DST 专用服务器默认：Master 分片 10999，Caves 分片 10998。
# 客户端开房时也使用同一套默认值，但玩家可以在开房界面改，所以工具会
# 优先从系统 UDP 监听表里读取进程真实占用的端口。
DEFAULT_MASTER_PORT = 10999
DEFAULT_CAVES_PORT = 10998
DEFAULT_PORTS = (DEFAULT_MASTER_PORT, DEFAULT_CAVES_PORT)

# Windows 默认的动态端口起始值；低于它的 0.0.0.0 绑定才可能是游戏监听口。
EPHEMERAL_PORT_START = 49152


def pick_master_port(ports) -> int:
    """从一组监听端口里挑出**主世界**（Master 分片）端口。

    注意不能用 ``min()``：DST 里主世界默认 10999、洞穴（Caves）默认 10998，
    取最小反而会选到**洞穴**端口，而客户端是连不进洞穴分片的。
    所以优先认 10999，只有在列表里没有它时才退而求其次取最小值。
    """
    ports = list(ports)
    if not ports:
        return DEFAULT_MASTER_PORT
    if DEFAULT_MASTER_PORT in ports:
        return DEFAULT_MASTER_PORT
    return min(ports)

# 防火墙规则名前缀（删除自己加的规则时靠它识别，不会误删别人的）
FIREWALL_RULE_PREFIX = "DST-IP-Join"
UPNP_MAPPING_DESC_PREFIX = "DST-IP-Join"

# --------------------------------------------------------------------------
# 网络检测用的外部服务
# --------------------------------------------------------------------------
# STUN 服务器：前几个在国内可达性较好。用于拿到 NAT 出口映射、判断 NAT 类型。
STUN_SERVERS = (
    ("stun.miwifi.com", 3478),
    ("stun.qq.com", 3478),
    ("stun.chat.bilibili.com", 3478),
    ("stun.cloudflare.com", 3478),
    ("stun.l.google.com", 19302),
)

# 公网 IP 查询接口：(名称, URL)。返回内容里用正则抓第一个合法 IPv4。
PUBLIC_IP_APIS = (
    ("4.ipw.cn", "https://4.ipw.cn"),
    ("ip.sb", "https://ipv4.ip.sb"),
    ("3322.net", "http://ip.3322.net"),
    ("ipip.net", "https://myip.ipip.net"),
    ("ipify", "https://api.ipify.org"),
    ("icanhazip", "https://ipv4.icanhazip.com"),
)

# 单个 HTTP 请求超时（秒）
HTTP_TIMEOUT = 6.0
STUN_TIMEOUT = 1.5
STUN_RETRIES = 2
# 最多探测几台 STUN 服务器（每台失败最多耗时 STUN_TIMEOUT*STUN_RETRIES）
STUN_MAX_SERVERS = 3
UPNP_SOAP_TIMEOUT = 6.0
SSDP_DISCOVER_TIMEOUT = 3.0

# --------------------------------------------------------------------------
# 网络判定
# --------------------------------------------------------------------------
# 运营商级 NAT（CGNAT）网段。落在这个段里的「公网 IP」其实还是内网，
# 端口映射/UPnP 一律无效，只能走内网穿透或虚拟局域网。
CGNAT_NETWORK = "100.64.0.0/10"

# 本机配置文件存放目录（用于记住上次的端口等设置）
CONFIG_DIR_NAME = "DST-IP-Join"
