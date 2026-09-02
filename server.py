from probes import grab_banner, probe_http, probe_https

#常见服务字典
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
}

#识别常见服务
def identify_service(port):
    return COMMON_SERVICES.get(port, "unknown")

def detect_service(host, port, timeout):
    #初步猜测
    service_hint = identify_service(port)

     #https
    if service_hint == "https":
        https_info = probe_https(host,port,timeout)
        if https_info is not None:
            return {
                "service": "https",
                "banner": None,
                "detail": https_info
            }

     #http
    if service_hint == "http":
        http_info = probe_http(host, port, timeout)
        if http_info is not None:
            return {
                        "service": "http",
                        "banner": None,
                        "detail": http_info
                        }
    
    #非标准端口：->http ->https -> banner ->最初结果 做快速指纹探测
    http_info = probe_http(host, port, timeout)
    if http_info is not None:
        return {
                    "service": "http",
                    "banner": None,
                    "detail": http_info
                    }
        
    https_info = probe_https(
        host,
        port,
        timeout
    )
    if https_info:
        return {
            "service": "https",
            "banner": None,
            "detail": https_info
        }
    
    banner = grab_banner(host, port, timeout)
    banner_service = identify_banner_service(banner)
    if banner_service:
        return {
            "service": banner_service,
            "banner": banner,
            "detail": {}
        }
    
    #全部失败 返回初始端口映射结果
    return {
        "service": service_hint,
        "banner": banner,
        "detail": {}
    }

# banner识别
def identify_banner_service(banner):

    if not banner:
        return None

    banner_lower = banner.lower()

    if "ftp" in banner_lower:
        return "ftp"

    if "smtp" in banner_lower:
        return "smtp"

    if "mysql" in banner_lower:
        return "mysql"

    if "redis" in banner_lower:
        return "redis"

    if banner.startswith("SSH-"):
        return "ssh"

    return None