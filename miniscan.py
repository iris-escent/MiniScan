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

scan_port("127.0.0.1", 80)