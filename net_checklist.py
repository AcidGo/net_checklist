# -*- coding: utf8 -*-

# Author: AcidGo
# Usage: check network acl on host from list ini file.
#   checklist: 指定列表 URL 资源地址。
#   socket_timeout: socket 扫描时的超时设置，单位为秒。
#   concurrency: 网络探测的并发度，默认为 1。
# Example:
#   list ini like it:
#       [inventory.A]
#       host1.A
#       host2.A
#       [inventory.B]
#       host1.B
#       [acl.A]
#       host1.dst.A:8001
#       host1.dst.A:8002
#       [acl.B]
#       host1.dst.B:9001

import array
import fcntl
import logging
import platform
import psutil
import re
import socket
import struct
from ConfigParser import ConfigParser
from sys import version_info
from urllib2 import urlopen

# CONFIG
LOG_LEVEL = "debug"

CHECKLIST_INVENTORY_PREFIX = "inventory."
CHECKLIST_INVENTORY_MAP_KEY = "inventory"
CHECKLIST_ACL_PREFIX = "acl."
CHECKLIST_ACL_MAP_KEY = "acl"
# EOF CONFIG

def init_logger(level, logfile=None):
    """日志功能初始化。
    如果使用日志文件记录，那么则默认使用 RotatinFileHandler 的大小轮询方式，
    默认每个最大 10 MB，最多保留 5 个。

    Args:
        level: 设定的最低日志级别。
        logfile: 设置日志文件路径，如果不设置则表示将日志输出于标准输出。
    """
    import os
    import sys
    if not logfile:
        logging.basicConfig(
            level = getattr(logging, level.upper()),
            format = "%(asctime)s [%(levelname)s] %(message)s",
            datefmt = "%Y-%m-%d %H:%M:%S"
        )
    else:
        logger = logging.getLogger()
        logger.setLevel(getattr(logging, level.upper()))
        if logfile.lower() == "local":
            logfile = os.path.join(sys.path[0], os.path.basename(os.path.splitext(__file__)[0]) + ".log")
        handler = RotatingFileHandler(logfile, maxBytes=10*1024*1024, backupCount=5)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logging.info("Logger init finished.")

def url_test(url, timeout=5):
    """测试 url 是否在超时范围内可达。

    Args:
        url: 测试 URL。
        timeout: 超时秒数。
    Returns:
        <bool>: 测试通过与否。
    """
    from urllib2 import urlopen, URLError
    try:
        urlopen(url, timeout = int(timeout))
    except Exception as e:
        return False
    else:
        return True

def get_local_address(is_multi=False):
    """获取服务器的本地 IP 地址。

    Args:
        is_multi: 是否获取本地可捕获的全部地址信息，但依旧不会包含 lo 回环地址
    Returns:
        res: <list>
    """
    res = []
    if not is_multi:
        if "EASYOPS_LOCAL_IP" in globals() and globals().get("EASYOPS_LOCAL_IP") != "":
            return [EASYOPS_LOCAL_IP]
        return [get_preferred_ipaddres()]
    else:
        for net in list_all_netcards():
            res.append(get_ip_address(net))
            res.remove("127.0.0.1")
        return res

def get_ip_address(ifname):
    """
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if version_info.major == 3:
        ifname_ = bytes(ifname[:15], "utf-8")
    else:
        ifname_ = ifname[:15]
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname_)
    )[20:24])

def get_default_gateway():
    """
    """
    if platform.system() == "Linux":
        return get_default_gateway_linux()
    else:
        logging.error("not support the system platform for getting default gateway")
        return None

def get_default_gateway_linux():
    """Read the default gateway directly from /proc.
    from https://stackoverflow.com/questions/2761829/python-get-default-gateway-for-a-local-interface-ip-address-in-linux

    Returns:
        <string>: gateway address.
    """
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def get_preferred_ipaddres():
    """选择合适的当期主机内的 IP 地址。
    使用报文协议获取所有IP，然后选择默认网关同网段的IP地址返回。

    Returns:
        <str> ip: 合适的IP地址，可能返回 None。
    """
    ip_lst = []
    for net in list_all_netcards():
        ip_lst.append(get_ip_address(net))

    if len(ip_lst) == 0:
        return None
    if len(ip_lst) == 2 and '127.0.0.1' in ip_lst:
        ip_lst.remove("127.0.0.1")
        return ip_lst[0]
    gateway = get_default_gateway()
    if not gateway:
        return None
    gateway_prefix = '.'.join(gateway.split('.')[0:-1])
    res = None
    for i in ip_lst:
        if i.startswith(gateway_prefix):
            res = i
            break
    return res

def list_all_netcards():
    """获取当前系统的所有可见网卡。

    Returns:
        <list> netcards_lst: 网卡集合。
    """
    if hasattr(psutil, "net_if_addrs"):
        addrs = psutil.net_if_addrs()
        return addrs.keys()
    else:
        max_possible = 128
        bytes = max_possible * 32
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack("iL", fcntl.ioctl(
            s.fileno(),
            0x8912,
            struct.pack("iL", bytes, names.buffer_info()[0])
        ))[0]
        name_str = names.tostring()
        lst = []
        for i in range(0, outbytes, 40):
            name = name_str[i:i+16].split('\0', 1)[0]
            lst.append(name)
        return lst


def parse_checklist(url):
    """解析 checklist 文件，得到如下字典形式：
        {
            "inventory": {"A": ["host1", "host2"], "B": ["host3"]},
            "acl": {"A": ["dst1:p1", "dst1:p2"], "B": ["dst2:p1"]},
        }

    Args:
        url: 资源路径。
    Returns:
        res: <dict>
    """
    if not url_test(url):
        raise Exception("cannot access the checklist url: {!s}".format(url))
    config = ConfigParser(allow_no_value=True)
    r = urlopen(url)
    config.readfp(r)
    res = {CHECKLIST_INVENTORY_MAP_KEY: {}, CHECKLIST_ACL_MAP_KEY: {}}
    for s in config.sections():
        s_key = ""
        s_flag = None
        if s.startswith(CHECKLIST_INVENTORY_PREFIX):
            s_key = "".join(s.split(CHECKLIST_INVENTORY_PREFIX)[1:])
            s_flag = CHECKLIST_INVENTORY_MAP_KEY
        elif s.startswith(CHECKLIST_ACL_PREFIX):
            s_key = "".join(s.split(CHECKLIST_ACL_PREFIX)[1:])
            s_flag = CHECKLIST_ACL_MAP_KEY
        else:
            logging.warning("invalid section name in the checklist ini: {!s}".format(s))
            continue
        if s_key not in res[s_flag]:
            res[s_flag][s_key] = []
        for i in config.items(s):
            if i[0] is None:
                continue
            i_key = i[0].strip()
            res[s_flag][s_key].append(i_key)

    # checking acl format must be <str>:<int>
    for acl_list in res[CHECKLIST_ACL_MAP_KEY].values():
        for i in acl_list:
            if not re.search(r"^.*?:\d+", i):
                raise Exception("found an invalid acl format: {!s}".format(i))
            port = int(i.split(":")[-1])
            if port < 1 or port > 65535:
                raise Exception("found an invalid acl port: {!s}".format(i))

    logging.debug("after parse checklist ini, get the res:")
    logging.debug(res)
    return res

def tcp_test(host, port, timeout=5):
    """
    """
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.settimeout(timeout)
    try:
        rc = socks.connect_ex((host, port))
    except Exception as e:
        logging.error("get an error when test tcp: {!s}:{!s}".format(host, str(port)))
        rc = -999
    finally:
        socks.close()
    return True if rc == 0 else False

def execute(checklist_url, socket_timeout, concurrency):
    """
    """
    if socket_timeout < 1 or socket_timeout > 100:
        raise Exception("not support the socket_timeout: {!s}".format(str(socket_timeout)))
    if concurrency != 1:
        raise Exception("only support concurrency is 1, sorry ...")

    cl_dict = parse_checklist(checklist_url)
    chk_res = {}
    local_ip = get_local_address()[0]
    s_name = None
    acl_list = []

    for s_k, s_v in cl_dict[CHECKLIST_INVENTORY_MAP_KEY]:
        if local_ip in s_v:
            s_name = s_k
    if s_name is None:
        logging.info("the local host {!s} is not in the inventory, exit.".format(local_ip))
        return 

    acl_list = cl_dict[CHECKLIST_ACL_MAP_KEY].get(s_name, [])
    if len(acl_list) == 0:
        logging.warning("the acl list is empty from {!s}".format(s_name))
        return 

    for dst in acl_list:
        dst_host = dst.split(":")[0].strip()
        dst_port = int(dst.split(":")[-1].strip())
        if tcp_test(dst_host, dst_port, socket_timeout):
            chk_res[dst] = "PASS"
        else:
            chk_res[dst] = "FAIL"

    logging.info("done all jobs")

