import socket
import errno
import os
import time #计时器
from concurrent.futures import ThreadPoolExecutor, as_completed #高级并发模块-异步任务-线程池类
import argparse #命令行参数解析

#端口扫描
def scan_port(host,port,timeout):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    #使用socket 模块的 socket 类，使用 IPv4 地址，TCP 协议
    sock.settimeout(timeout) 
    result = sock.connect_ex((host, port)) 
    #非阻塞式的连接函数，尝试连接远程服务器 TCP三次握手,错误返回错误码
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
    type=float, #自动类型转化
    default=1.0,
    help="Connection timeout in seconds, default: 1.0"
)

args = parser.parse_args()
host = args.host
ports_text = args.ports
workers = args.threads
timeout = args.timeout

#输入检查
if  workers < 1 or workers > 500:
    parser.error("threads must be between 1 and 500")
if timeout <=0:
    parser.error("timeout must be greater than 0")

try:
    ports = parse_ports(ports_text)
    start_time = time.perf_counter()  #获取时间戳，测试短时间内代码性能

    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        #提交任务
        for port in ports:
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

    # 输出结果
    results.sort(key=lambda x: x["port"]) #最终输出的时候按端口号排列
    for result in results:
        if result["status"] == "open":
            print(f"[+] {result["host"]}:{result["port"]} open")
        else:
            print(f"[-] {result["host"]}:{result["port"]} not open")

    end_time = time.perf_counter()
    print(f"[*]  Scan finished in {end_time - start_time:.2f} seconds")

except ValueError as e:
    print(f"[!] Invalid port input: {e}")