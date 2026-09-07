# iScan

**轻量级 TCP 端口扫描与服务识别工具（Python 实现）**

`iScan` 支持单个 IPv4 地址和 CIDR 网段，可执行主机发现、并发端口扫描、服务识别，并将结果输出到终端或 JSON 文件。

> 仅用于扫描自己拥有或已获得明确授权的主机和网段。

## 功能

- 扫描单个 IPv4 地址或 CIDR 网段
- 支持单端口、多端口、端口范围和预设端口组
- 通过 ICMP 和常用 TCP 端口发现存活主机
- 并发执行 TCP 连接扫描，区分开放、关闭、超时和错误状态
- 识别常见服务并获取 Banner
- 主动探测 HTTP、HTTPS 和 Redis 服务
- 在终端显示结果，或保存为 JSON 文件

## 环境要求

- Linux 或 WSL
- Python 3
- 系统提供 `ping` 命令

项目仅使用 Python 标准库，不需要安装第三方依赖。

## 快速开始

在 `iscan.py` 所在目录运行：

```bash
python3 iscan.py --help
```

### 扫描单台主机的主要端口

```bash
python3 iscan.py -H 10.10.10.10 -p main --open
```

扫描 `10.10.10.10` 的 `main` 端口组，只显示开放端口。

### 扫描一个网段的常见端口

```bash
python3 iscan.py -H 192.168.1.0/24 -p common --open
```

扫描 `192.168.1.1-192.168.1.254`，先发现存活主机，再检查常见端口。

### 扫描 Web 相关端口并保存结果

```bash
python3 iscan.py -H 192.168.1.0/24 -p web --open -o web-assets.json
```

扫描 Web 服务、管理后台和中间件常用端口，将结果保存到 `web-assets.json`。

### 跳过主机发现

```bash
python3 iscan.py -H 10.10.10.10 -p 22,80,443 --no-ping
```

不执行 ICMP/TCP 存活预探测，直接扫描指定端口。适用于目标不响应 ICMP 的情况。

### 其他示例

扫描数据库和消息队列常用端口：

```bash
python3 iscan.py -H 192.168.1.0/24 -p db --open -o db-assets.json
```

扫描全部 `1-65535` 端口：

```bash
python3 iscan.py -H 10.10.10.10 -p all --open -o full-scan.json
```

全端口扫描耗时较长，并可能触发防火墙或安全设备告警。

## CLI 参数

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `-H, --host` | 目标 IPv4 地址或 CIDR 网段 | 必填 |
| `-p, --ports` | 端口、端口范围或端口组 | `main` |
| `-t, --threads` | 并发线程数，范围 `1-500` | `50` |
| `--timeout` | 单次连接超时时间，单位为秒 | `1.0` |
| `--no-ping` | 跳过主机发现，直接扫描端口 | 关闭 |
| `--open` | 只显示开放端口 | 关闭 |
| `-o, --output` | 将结果保存为 JSON 文件 | 无 |
| `-v, --verbose` | 显示详细日志 | 关闭 |

`-p` 支持以下格式：

```text
-p 80                    # 单端口
-p 22,80,443             # 多端口
-p 8000-8100             # 端口范围
-p common                # 预设端口组
-p main,8081,9000-9010   # 端口组与自定义端口混用
```

## 端口组

| 分组 | 范围 |
| --- | --- |
| `main` | 常用服务、中间件和大数据组件端口，约 130 个 |
| `common` | SSH、HTTP、HTTPS、SMB、RDP 等常见服务端口 |
| `web` | Web 服务、管理后台和中间件常用端口 |
| `db` | 数据库和消息队列常用端口 |
| `service` | SSH、SMB、LDAP、RDP、WinRM、MQTT 等基础服务端口 |
| `all` | 全部 `1-65535` 端口 |

## 输出示例

```text
INFO: iScan starting...
INFO: Targets : 1
INFO: Ports   : 3
[+] Host 10.10.10.10 alive (icmp)
INFO: Alive   : 1
INFO: Tasks   : 3
[+] 10.10.10.10:22 open ssh
    Banner: SSH-2.0-OpenSSH_8.9p1
[+] 10.10.10.10:80 open http
    Status: 200
    Server: nginx/1.24.0
    Title: Welcome to nginx!

[*] Open    : 2
[*] Closed  : 1
[*] Timeout : 0
[*] Error   : 0
[*] Total   : 3
```

- `alive`：主机存活
- `open`：端口开放
- `closed`：端口关闭
- `timeout`：连接超时，可能由网络或防火墙策略导致
- `error`：扫描过程发生错误
- `Banner`：服务返回的标识或版本信息

## 项目结构

| 文件 | 职责 |
| --- | --- |
| [`iscan.py`](iscan.py) | CLI 入口、任务编排和报告生成 |
| [`scanner.py`](scanner.py) | TCP 端口扫描与并发调度 |
| [`discovery.py`](discovery.py) | ICMP 和 TCP 主机发现 |
| [`server.py`](server.py) | 服务识别与探针调度 |
| [`probes.py`](probes.py) | Banner、HTTP、HTTPS 和 Redis 探测 |
| [`port_groups.py`](port_groups.py) | 端口组定义与解析 |
| [`tests/`](tests/) | 单元测试 |
