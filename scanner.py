import socket
import errno
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

#端口扫描
def scan_port(host,port,timeout):
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #socket 模块， IPv4 地址，TCP 协议
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        #尝试连接远程服务器 TCP三次握手,错误返回错误码
    except OSError as exc:
        return {
            "host": host,
            "port": port,
            "status": "error",
            "code": exc.errno,
            "error": str(exc)
        }
    finally:
        if sock is not None:
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

# 有界批量调度
def scan_ports(hosts, ports, workers, timeout, on_submit=None):
    targets = (
        (host, port)
        for host in hosts
        for port in ports
    )
    results = []
    max_pending = max(1, workers * 2)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {}

        def submit_next():
            try:
                host, port = next(targets)
            except StopIteration:
                return False

            if on_submit is not None:
                on_submit(host, port)

            future = executor.submit(
                scan_port,
                host,
                port,
                timeout
            )
            pending[future] = (host, port)
            return True

        for _ in range(max_pending):
            if not submit_next():
                break

        while pending:
            completed, _ = wait(
                pending,
                return_when=FIRST_COMPLETED
            )

            for future in completed:
                host, port = pending.pop(future)

                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "host": host,
                        "port": port,
                        "status": "error",
                        "code": getattr(exc, "errno", None),
                        "error": str(exc)
                    }

                results.append(result)
                submit_next()

    return results
