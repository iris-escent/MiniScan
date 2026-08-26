import socket


#端口扫描(存活端口探测)
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