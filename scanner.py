import socket
import errno

#端口扫描
def scan_port(host,port,timeout):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    #socket 模块， IPv4 地址，TCP 协议
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
    elif result == errno.ECONNREFUSED:
        status = "closed"
    elif result in (errno.ETIMEDOUT, errno.EAGAIN):
        status = "timeout"
    else:
        status = "error"

    return {
        "host": host,
        "port": port,
        "status": status,
        "code": result
    }