import math
import subprocess  # 运行系统命令
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import scan_port


TCP_PROBE_PORTS = (80, 443, 22, 445) #常用探测端口

def ping_host(host, timeout):
    wait_seconds = max(1, math.ceil(timeout))

    command = [
        "ping",
        "-c", "1", # count计数 1台
        "-W", str(wait_seconds),
        host
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=wait_seconds + 1, # 给进程本身启动关闭的缓冲时间
            check=False
        )
    except FileNotFoundError:
        return {
            "host": host,
            "status": "error",
            "method": "icmp",
            "code": None,
            "error": "ping command not found"
        }
    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "status": "no_response",
            "method": "icmp",
            "code": None,
            "error": "ping command timeout"
        }

    if completed.returncode == 0:
        status = "alive" # 主机存活
        error = None
    elif completed.returncode == 1:
        status = "no_response"
        error = None
    else:
        status = "error"
        error = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "ping command failed"
        )

    return {
        "host": host,
        "status": status,
        "method": "icmp",
        "code": completed.returncode,
        "error": error
    }



# TCP 补充存活探测
def tcp_probe_host(host, timeout):
    last_code = None

    for port in TCP_PROBE_PORTS:
        result = scan_port(
            host,
            port,
            timeout
        )

        last_code = result["code"]

        if result["status"] in ("open", "closed"):
            return {
                "host": host,
                "status": "alive",
                "method": f"tcp/{port}",
                "code": last_code,
                "error": None
            }

    return {
        "host": host,
        "status": "no_response",
        "method": "tcp",
        "code": last_code,
        "error": None
    }

# 成功立刻停止
def check_host_alive(host, timeout):
    ping_result = ping_host(host, timeout)

    if ping_result["status"] == "alive":
        return ping_result

    tcp_result = tcp_probe_host(host, timeout)

    if tcp_result["status"] == "alive":
        return tcp_result

    return {
        "host": host,
        "status": "no_response",
        "method": "icmp+tcp",
        "code": tcp_result["code"],
        "error": (
            ping_result["error"]
            if ping_result["status"] == "error"
            else None
        )
    }

# 并发探测多个主机
def discover_hosts(hosts, workers, timeout):
    if not hosts:
        return []

    worker_count = min(workers, len(hosts))
    results = []

    with ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:
        futures = []

        for host in hosts:
            future = executor.submit(
                check_host_alive,
                host,
                timeout
            )
            futures.append(future)

        for future in as_completed(futures):
            results.append(future.result())

    results.sort(
        key=lambda result: ipaddress.ip_address(
            result["host"]
        )
    )

    return results