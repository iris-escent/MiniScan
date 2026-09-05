import socket
import errno
import os
import time #计时器
import argparse #命令行参数解析
import ipaddress  #处理 IP 和网络地址
import re #正则
import html
import ssl  # SSL/TLS模块
import json 
import logging

from scanner import scan_ports
from server import detect_service
from datetime import datetime 
from discovery import discover_hosts
from port_groups import parse_ports

#设置日志
logging.basicConfig(
    level=logging.INFO, # 设置日志级别
    format="%(levelname)s: %(message)s",  #设置日志格式
)
logger = logging.getLogger("MiniScan") #创建日志器

#解析ip地址
def parse_hosts(host_text):
    host_text = host_text.strip()
    if '/' in host_text:
        network = ipaddress.IPv4Network(host_text,strict=False) #一个CIDR网络对象
        hosts = []
        for host in network.hosts(): #所有可用ip地址
            hosts.append(str(host))

        return hosts
    ip = ipaddress.IPv4Address(host_text)
    return [str(ip)]

# 输出确认存活的主机
def print_alive_hosts(host_results):
    for result in host_results:
        if result["status"] != "alive":
            continue

        print(
            f"[+] Host {result['host']} alive "
            f"({result['method']})"
        )


def host_results_from_open_ports(hosts, results):
    first_open_port = {}

    for result in results:
        if result["status"] == "open":
            first_open_port.setdefault(
                result["host"],
                result["port"]
            )

    host_results = []
    for host in hosts:
        port = first_open_port.get(host)

        if port is not None:
            host_results.append({
                "host": host,
                "status": "alive",
                "method": f"tcp/{port}",
                "code": 0,
                "error": None
            })
        else:
            host_results.append({
                "host": host,
                "status": "no_response",
                "method": "port_scan",
                "code": None,
                "error": None
            })

    return host_results


def print_result(results,open_only=False):
    # 打印结果
    for result in results:

        if open_only and result["status"] != "open":
            continue

        if result["status"] == "open":
            print(f'[+] {result["host"]}:{result["port"]} '
                f'open {result["service"]}'
                )
            if result["banner"]:
                print(f'    Banner: {result["banner"]}')
            if result["detail"]:
                if result["detail"].get("status_code"):
                    print(
                        f'    Status: '
                        f'{result["detail"]["status_code"]}'
                    )

                if result["detail"].get("server"):
                    print(
                        f'    Server: '
                        f'{result["detail"]["server"]}'
                    )

                if result["detail"].get("title"):
                    print(
                        f'    Title: '
                        f'{result["detail"]["title"]}'
                    )

        elif result["status"] == "closed":
            print(
                f"[-] {result['host']}:{result['port']} closed"
            )
        elif result["status"] == "timeout":
            print(
                f"[!] {result['host']}:{result['port']} timeout"
            )
        else:
            print(
                f"[!] {result['host']}:{result['port']} error "
                f"(code={result['code']})"
    )

#端口汇总统计
def print_summary(results):
    total = len(results)

    open_count = sum(
        1 for result in results
        if result["status"] == "open"
    )

    closed_count = sum(
        1 for result in results
        if result["status"] == "closed"
    )

    timeout_count = sum(
        1 for result in results
        if result["status"] == "timeout"
    )

    error_count = sum(
        1 for result in results
        if result["status"] == "error"
    )

    print()
    print(f"[*] Open    : {open_count}")
    print(f"[*] Closed  : {closed_count}")
    print(f"[*] Timeout : {timeout_count}")
    print(f"[*] Error   : {error_count}")
    print(f"[*] Total   : {total}")


#输出结构化
def build_report(results, host_results, ports, start_time, end_time):

    services = [
        r for r in results
        if r["status"] == "open"
    ]
    alive_results = [
        result
        for result in host_results
        if result["status"] == "alive"
    ]
    no_response_count = sum(
        1
        for result in host_results
        if result["status"] == "no_response"
    )
    report = {
        "scan_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "duration_seconds": round(end_time - start_time, 2),
        "summary": {
            "total_hosts": len(host_results),
            "alive_hosts": len(alive_results),
            "no_response_hosts": no_response_count,
            "total_ports": len(ports),
            "total_services": len(services)
        },

        "hosts": []
    }
    for host_result in alive_results:
        host = host_result["host"]
        host_info = {
            "host": host,
            "status": host_result["status"],
            "method": host_result["method"], #icmp、tcp/80
            "ports": []
        }
        for result in services:
            if result["host"] == host:
                port_info = {
                    "port": result["port"],
                    "service": result.get(
                        "service",
                        "unknown"
                    ),
                }

                if result.get("banner"):
                    port_info["banner"] = result["banner"]

                if result.get("detail"):
                    port_info["detail"] = result["detail"]

                host_info["ports"].append(
                    port_info
                )
        report["hosts"].append(
            host_info
        )
    return report



#输入
parser = argparse.ArgumentParser( #创建参数解析器对象的构造函数
    description="MiniScan - A lightweight TCP port scanner"
)
parser.add_argument(
    "-H",
    "--host",
    required=True,
    help="Target host"
)
parser.add_argument(
    "-p",
    "--ports",
    default="main",
    help=(
        "Ports or groups: common, web, db, service, main, all; "
        "default: main"
    )
)
parser.add_argument(
    "-t",
    "--threads",
    type=int, #自动类型转化
    default=50,
    help="Number of worker threads, default: 50"
)
parser.add_argument(
    "--timeout",
    type=float, 
    default=1.0,
    help="Connection timeout in seconds, default: 1.0"
)
parser.add_argument(
    "-o",
    "--output",
    help="save result to json file"
)
parser.add_argument(
    "-v",
    "--verbose", #控制输出信息的详细程度
    action="store_true",  # 动作类型：存储布尔值
    help="show detailed information"
)
parser.add_argument(
    "--open",
    action="store_true",
    help="show only open ports"
)
parser.add_argument(
    "--no-ping",
    action="store_true",
    help="skip host discovery and scan target ports directly"
)

args = parser.parse_args()
if args.verbose :
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

try:
    hosts = parse_hosts(args.host)
except ValueError as e:
    parser.error(f"invalid host or CIDR: {e}")
ports_text = args.ports
workers = args.threads
timeout = args.timeout
verbose = args.verbose
open_only = args.open
no_ping = args.no_ping

#输入检查
if  workers < 1 or workers > 500:
    parser.error("threads must be between 1 and 500")
if timeout <=0:
    parser.error("timeout must be greater than 0")

try:
    ports = parse_ports(ports_text)

    # 添加扫描摘要
    logging.info("MiniScan starting...")
    logging.info(f"Targets : {len(hosts)}")
    logging.info(f"Ports   : {len(ports)}")
    logging.info(f"Threads : {workers}")
    logging.info(f"Timeout : {timeout}s")
    print()


    start_time = time.perf_counter()  #获取时间戳，测试短时间内代码性能

    #存活探测
    if no_ping:
        logger.info("Discovery: skipped")
        scan_hosts = hosts
        host_results = None
    else:
        host_results = discover_hosts(hosts, workers, timeout)
        print_alive_hosts(host_results)

        scan_hosts = [
            result["host"]
            for result in host_results
            if result["status"] == "alive"
        ]

        no_response_hosts = [
            result["host"]
            for result in host_results
            if result["status"] == "no_response"
        ]

        logger.info(f"Alive   : {len(scan_hosts)}")
        logger.info(f"No reply: {len(no_response_hosts)}")

    total_tasks = len(scan_hosts) * len(ports)
    logger.info(f"Tasks   : {total_tasks}")

    results = scan_ports(
        scan_hosts,
        ports,
        workers,
        timeout,
        on_submit=lambda host, port: logger.debug(
            f"submit scan task {host}:{port}"
        )
    )

    # 排序
    results.sort(key=lambda x:(
                ipaddress.ip_address(x["host"]),
                 x["port"]
                 ) )
    # 补充info
    for result in results:
        logger.debug(
            f"detect service {result['host']}:{result['port']}"
        )
        if result["status"] == "open":
            service_info = detect_service(result["host"], result["port"], timeout)
            result.update(service_info) #合并结果

    if no_ping:
        host_results = host_results_from_open_ports(
            hosts,
            results
        )
        print_alive_hosts(host_results)

        alive_count = sum(
            1 for result in host_results
            if result["status"] == "alive"
        )
        logger.info(f"Alive   : {alive_count}")
        logger.info(f"No asset: {len(hosts) - alive_count}")

    print_result(results, open_only=open_only)
    print_summary(results)

    end_time = time.perf_counter()

    report = build_report(
    results,
    host_results,
    ports,
    start_time,
    end_time
)
    
    logger.info(f"Scan finished in {end_time - start_time:.2f} seconds")
    #输出json
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
            #json.dump 将JSON 写入文件
            #indent格式化输出，每层缩进4个空格 ensure_ascii保留中文等非ASCII字符,不要转义
        print(f"[*] Result saved to {args.output}")

except ValueError as e:
    print(f"[!] Invalid port input: {e}")
