import socket
import errno
import os

def scan_port(host,port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    #使用socket 模块的 socket 类，使用 IPv4 地址，TCP 协议
    sock.settimeout(1) 

    result = sock.connect_ex((host, port)) 
    #非阻塞式的连接函数，尝试连接远程服务器 TCP三次握手,错误返回错误码

    if result == 0:
        print(f"[+] {host}:{port} open")
    else:
        error_name = errno.errorcode.get(result,"unknow")
        error_msg = os.strerror(result)

        print(
            f"[-] {host}:{port} not open,"  #这样换行
            f"code={result}, {error_name}:{error_msg}"
            )

    sock.close()

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


host = input("host: ").strip()
ports_text = input("ports: ")

try:
    ports = parse_ports(ports_text)

    for port in ports:
        scan_port(host, port)

except ValueError as e:
    print(f"[!] Invalid port input: {e}")