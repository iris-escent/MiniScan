import socket
import ssl
import re
import html

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

