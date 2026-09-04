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

# 自建服务端口探测库
HTTP_PORTS = {
    80, 81, 3000, 5000,
    8000, 8001, 8080, 8081, 8888
}

HTTPS_PORTS = {
    443, 4443, 7443, 8443, 9443
}


#识别常见服务
def identify_service(port):
    return COMMON_SERVICES.get(port, "unknown")

#探测方法选择
def select_probes(port):
    if port in HTTPS_PORTS:
        return ["https", "http"]
    if port in HTTP_PORTS:
        return ["http", "https"]

    return ["http", "https"]

# 调用对应探针+结果包装
def run_probe(probe_name, host, port, timeout):
    if probe_name == "http":
        detail = probe_http(host, port, timeout)

        if detail is None:
            return None

        return {
            "service": "http",
            "banner": None,
            "detail": detail
        }

    if probe_name == "https":
        detail = probe_https(host, port, timeout)

        if detail is None:
            return None

        return {
            "service": "https",
            "banner": None,
            "detail": detail
        }

    raise ValueError(f"unknown probe: {probe_name}")



def detect_service(host, port, timeout):
    service_hint = identify_service(port)

    # 始终先读取初始 Banner
    banner = grab_banner(host, port, timeout)
    banner_service = identify_banner_service(banner)

    if banner_service is not None:
        return {
            "service": banner_service,
            "banner": banner,
            "detail": {}
        }
    # Banner未识别，再发送主动探针
    for probe_name in select_probes(port):
        result = run_probe(
            probe_name,
            host,
            port,
            timeout
        )

        if result is not None:
            return result

    # 所有探测失败，保留初始Banner
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

    if "ftp" in banner_lower: return "ftp"
    if "smtp" in banner_lower: return "smtp"
    if "mysql" in banner_lower: return "mysql"
    if "redis" in banner_lower: return "redis"
    if banner.startswith("SSH-"): return "ssh"

    return None