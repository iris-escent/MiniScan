import socket


host = "127.0.0.1"
port = 8000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
#使用socket 模块的 socket 类，使用 IPv4 地址，TCP 协议
sock.settimeout(1) 

result = sock.connect_ex((host, port)) 
#非阻塞式的连接函数，尝试连接远程服务器 TCP三次握手

if result == 0:
    print(f"[+] {host}:{port} open")
else:
    print(f"[-] {host}:{port} closed")

sock.close()


