import socket
import errno
import os
import time #计时器
from concurrent.futures import ThreadPoolExecutor, as_completed #高级并发模块-异步任务-线程池类
import argparse #命令行参数解析
import ipaddress  #处理 IP 和网络地址
import re #正则
import html
import ssl  # SSL/TLS模块
import json 
import logging


#设置日志
logging.basicConfig(
    level=logging.INFO, # 设置日志级别
    format="%(levelname)s: %(message)s",  #设置日志格式
)
logger = logging.getLogger("MiniScan") #创建日志器


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

#端口扫描
def scan_port(host,port,timeout):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    #socket 模块的 socket 类，使用 IPv4 地址，TCP 协议
    sock.settimeout(timeout) 
    result = sock.connect_ex((host, port)) 
    #尝试连接远程服务器 TCP三次握手,错误返回错误码
    sock.close()

    if result == 0:
        return {
            "host": host,
            "port": port,
            "status": "open",
            "code": result
        }

    return {
        "host": host,
        "port": port,
        "status": "not_open",
        "code": result
    }
            
#端口解析
def parse_ports(ports_text):
    ports = []

    for item in ports_text.split(","):
        item = item.strip()

        if not item:
            continue

        if "-" in item: # 扫描1-100
            start, end = item.split("-")
            start = int(start)
            end = int(end)
            if start > end : 
                raise ValueError("start port cannot be greater than end port")
            if start < 1 or end > 65535:
                raise ValueError("port must be between 1 and 65535")
            for port in range(start, end+1):
                ports.append(port)

        else:
            port = int(item)
            if port < 1 or port > 65535:
                 raise ValueError("port must be between 1 and 65535")
            ports.append(port)

    return ports

#识别常见服务
def identify_service(port):
    return COMMON_SERVICES.get(port, "unknown")

# 获取服务类型
def grab_banner(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host,port))
        banner = sock.recv(1024) #拿前1024字节数据
        return banner.decode(
            errors="ignore"
        ).strip()
    except (socket.timeout, OSError, ssl.SSLError):
        return None

    finally:
        sock.close()

# 解析http响应
def parse_http_response(response):

    lines = response.split("\r\n")
    status_line = lines[0]

    if not status_line.startswith("HTTP/"):
        return None

    parts = status_line.split()
    status_code = int(parts[1])

    server = None
    for line in lines:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()

    title = None
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        response,
        re.IGNORECASE | re.DOTALL
    )

    if match:
        title = match.group(1).strip()
        title = " ".join(title.split())
        title = html.unescape(title)


    return {
        "status_code": status_code,
        "server": server,
        "title": title
    }

#http探测
def probe_http(host,port,timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host,port))
        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())
        #拼接tcp字节流
        chunks = []
        while True:
            data = sock.recv(4096)

            if not data:
                break
            chunks.append(data)
        response = b"".join(chunks).decode(errors="ignore")

        return parse_http_response(response)

    except (socket.timeout, OSError) :
        return None

    finally:
        sock.close()

#https探测
def probe_https(host,port,timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host,port))
        context = ssl.create_default_context()  #创建TLS配置
        context.check_hostname = False  #不验证主机名
        context.verify_mode = ssl.CERT_NONE #不验证证书

        tls_sock = context.wrap_socket(sock, server_hostname=host)

        request = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"\r\n"
        )

        tls_sock.sendall(request.encode())
        #拼接tcp字节流
        chunks = []

        while True:
            data = tls_sock.recv(4096)

            if not data:
                break
            chunks.append(data)
        response = b"".join(chunks).decode(errors="ignore")
        return parse_http_response(response)

    except (socket.timeout, OSError) :
        return None

    finally:
        sock.close()


def detect_service(host, port, timeout):
    #初步猜测
    service_hint = identify_service(port)

    #ssh
    if service_hint == "ssh":
        banner = grab_banner(host, port, timeout)
        if banner:
            if banner.startswith("SSH-"):
                return {
                    "service": "ssh",
                    "banner": banner,
                    "detail": {}
                 }

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
    if banner and banner.startswith("SSH-"):
        return{
                "service": "ssh",
                "banner": banner,
                "detail": {}
        }
    
    #全部失败 返回初始端口映射结果
    return {
        "service": service_hint,
        "banner": banner,
        "detail": {}
    }

def print_result(results):
    # 打印结果
    for result in results:
        if result["status"] == "open":
            print(f"[+] {result["host"]}:{result["port"]} "
                f"open {result["service"]}"
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

        else:
            print(f"[-] {result["host"]}:{result["port"]} not open")


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
    required=True,
    help="Ports, e.g. 80,443 or 1-1000"
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

#输入检查
if  workers < 1 or workers > 500:
    parser.error("threads must be between 1 and 500")
if timeout <=0:
    parser.error("timeout must be greater than 0")

try:
    ports = parse_ports(ports_text)

    # 添加扫描摘要
    total_tasks = len(hosts)*len(ports)
    logging.info("MiniScan starting...")
    logging.info(f"Targets : {len(hosts)}")
    logging.info(f"Ports   : {len(ports)}")
    logging.info(f"Tasks   : {total_tasks}")
    logging.info(f"Threads : {workers}")
    logging.info(f"Timeout : {timeout}s")
    print()


    start_time = time.perf_counter()  #获取时间戳，测试短时间内代码性能

    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        #提交任务
        for host in hosts:
            for port in ports:
                logger.debug(
                   f"submit scan task {host}:{port}"
                )
                future = executor.submit(
                    scan_port,
                    host,
                    port,
                    timeout
                ) #submit 把scan_portree任务交给executor
                futures.append(future)
        #收集结果
        for future in as_completed(futures):
            results.append(future.result())

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

    print_result(results)

    end_time = time.perf_counter()
    logger.info(f"Scan finished in {end_time - start_time:.2f} seconds")
    #输出json
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
            #json.dump 将JSON 写入文件
            #indent格式化输出，每层缩进4个空格 ensure_ascii保留中文等非ASCII字符,不要转义
        print(f"[*] Result saved to {args.output}")

except ValueError as e:
    print(f"[!] Invalid port input: {e}")

