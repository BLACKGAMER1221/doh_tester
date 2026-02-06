
# 🔒 DoH-Tester

🇺🇸 [English](README.md) | 🇷🇺 [Русский](README-RU.md) | 🇨🇳 [中文](README-ZH.md) | 🇮🇷 [فارسی](README-FA.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

一个高性能、多线程的 DNS-over-HTTPS（DoH）端点测试工具，具备智能协议检测、可配置过滤以及自动化列表管理能力。

## 📋 简介

DoH-Tester 可在大规模场景下验证 DoH 端点，测试 TCP 连通性、TLS 握手以及通过多种协议（Wire 格式 GET/POST、JSON API）进行的真实 DNS 解析。该工具面向网络管理员、隐私倡导者以及需要在受限网络环境中维持可靠、未被审查的 DNS 解析能力的开发者。

---

### 核心特性

* ✅ TCP 连通性测试（IPv4 & IPv6）
* 🔐 TLS 握手验证（可选不安全模式）
* 🌐 DNS 解析方式：

  * DoH GET（Wire 格式）
  * DoH POST（Wire 格式）
  * DoH GET（JSON API）
* ⚡ 基于线程池的并行测试
* 🧠 智能分类（WORKING / FLAKY / BLOCKED）
* 📊 延迟测量（毫秒）
* 🧾 人类可读的表格输出
* 🧹 精简输出模式（仅 URL）
* 📦 可选 JSON 输出（自动时间戳或自定义文件名）
* 📁 通过 `config.json` 进行配置
* 🗂 可选：自动从源文件中清理可用端点

---

## 🎯 使用场景

| 场景         | DoH-Tester 的作用                           |
| ---------- | ---------------------------------------- |
| **绕过审查**   | 快速发现真正可用的 DoH 解析器，以绕过基于 DNS 的封锁并访问被过滤的平台 |
| **隐私工具维护** | 为 VPN、代理、隧道或浏览器配置维护可靠的 DoH 列表            |
| **性能优化**   | 测量延迟，找到你所在位置最快的解析器                       |
| **网络审计**   | 验证企业/ISP 网络中的 DoH 基础设施                   |
| **基础设施监控** | 对私有 DoH 服务器进行自动健康检查                      |

<details>
<summary><b>🔓 绕过审查（点击展开）</b></summary>

通过加密的 HTTPS 连接解析域名，访问 YouTube、Instagram、Twitter/X 及新闻网站等被过滤的平台，从而绕过基于 DNS 的过滤和 DNS 劫持。[gfw resist HTTPS proxy](https://github.com/GFW-knocker/gfw_resist_HTTPS_proxy)

**工作原理：**

* 标准 DNS 查询（UDP 53 端口）未加密，容易被防火墙拦截
* DoH 将 DNS 查询封装在 HTTPS 流量中（443 端口），与普通网页浏览流量无异
* 在高度审查的网络中尤为有用，例如：

  * 标准 DNS 被污染（返回错误 IP）
  * 域名在 DNS 解析器层面被封锁
  * 使用了 SNI 过滤，但 DNS 加密尚未被完全阻断

**重要说明：**例如，如果 VPN 或 Cloudflare 的 IP 在 **IP 层** 被封锁（防火墙直接丢弃发往这些 IP 的数据包），仅使用 DoH 无法恢复对这些特定 IP 的访问。但 DoH 仍可以帮助你：

1. 发现尚未被封锁的可用替代端点
2. 在仅 DNS 被封锁而 VPN IP 未被封锁的情况下，将 VPN 域名解析为 IP
3. 访问未被 IP 封锁的“域名前置”或备用 CDN 端点

</details>

<details>
<summary><b>🔐 隐私工具维护（点击展开）</b></summary>

当标准发现机制失效时，仍可维持对隐私基础设施的访问：

* **访问被封锁的 VPN 域名：** 如果你的 VPN 提供商域名（如 `vpn-provider.com`）被 DNS 劫持封锁，但其服务器 IP 并未被封锁，可使用可用的 DoH 端点解析真实服务器地址以维持连接。

* **DNS 隧道：** 使用已验证可用的 DoH 端点作为 DNS 隧道工具的传输层，例如：

  * [dnstt](https://www.bamsoftware.com/software/dnstt/)：基于 TCP-over-DNS 的隧道，可通过 DoH 解析器工作
  * [DNSCrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy)：可通过 DoH 并结合匿名中继
  * [Iodine](https://github.com/yarrick/iodine)：IP-over-DNS 隧道（需要 UDP，但可使用 DoH 进行引导）

* **反审查工具引导：** 许多反审查工具（Tor 网桥、Shadowsocks、WireGuard）在启动时需要先解析引导服务器。如果初始 DNS 查询被污染，工具将无法连接。通过 DoH 预先解析可获得正确 IP。

</details>

<details>
<summary><b>⚡ 性能优化（点击展开）</b></summary>

为你的网络环境找到最优解析器：

* 同时测量多个 DoH 端点的延迟
* 识别地理路由优化（某些 ISP 会路由到更近的 PoP）
* 对比 Wire 格式与 JSON API 实现之间的解析速度
* 构建基于位置自动选择最快解析器的列表

</details>

<details>
<summary><b>🏢 网络审计（点击展开）</b></summary>

验证 DoH 基础设施的可用性与合规性：

* 测试企业网络中可访问的公共 DoH 解析器
* 验证私有/内部 DoH 服务器是否正常响应
* 检测 TLS 中间人拦截（破坏 DoH 连接的设备）
* 生成展示网络各区域 DNS 隐私能力的合规报告

</details>

## ✨ 完整功能列表

<details>
<summary><strong>🔍 核心测试能力</strong></summary>

* **DoH 协议支持**：RFC 8484 DNS Wire 格式 GET/POST，以及 JSON API（兼容 Google / Cloudflare）
* **分层验证**：TCP 连通性 → TLS 握手 → DoH 应用层解析
* **智能协议检测**：在适用时自动测试 Wire 格式与 JSON API
* **双栈网络**：支持 IPv4 与 IPv6，并自动回退
* **ISP 安全测试**：执行真实 DNS 解析而不触发 DNS 污染或过滤

</details>

<details>
<summary><strong>⚡ 性能与可靠性</strong></summary>

* **并行测试引擎**：可配置线程池，实现高速端点测试
* **稳健的重试逻辑**：每个端点多次尝试，并可配置成功阈值
* **延迟测量**：毫秒级高精度计时
* **安全的 Ctrl+C 退出**：优雅关闭并保存部分结果
* **智能分类**：端点被标记为 **WORKING**、**FLAKY** 或 **BLOCKED**

</details>

<details>
<summary><strong>🔐 安全与诊断</strong></summary>

* **TLS 校验**：证书与握手验证，支持可选不安全模式
* **证书检查**：捕获 TLS 证书主体与加密套件信息
* **错误分类**：区分 TCP 阻断、TLS 拦截与 DoH 应用层失败
* **解析 IP 报告**：显示实际 DNS 解析结果以供验证

</details>

<details>
<summary><strong>📊 输出与报告</strong></summary>

* **灵活的输出格式**：

  * 人类可读表格
  * 仅 URL 的精简列表（适合脚本）
  * 机器可读的 JSON
* **时间戳输出**：自动 ISO 8601 时间戳（或自定义文件名）
* **结果排序**：JSON 输出按延迟排序（最快优先）
* **仅可用过滤**：仅显示或导出可用端点

</details>

<details>
<summary><strong>🗂 列表与文件管理</strong></summary>

* **自动清理模式**：从源列表中移除可用端点
* **备份保护**：修改输入文件前创建 `.backup` 文件
* **注释保留**：保留端点列表中的注释与格式
* **自愈列表**：帮助维护新鲜、可靠的 DoH 端点集合

</details>

<details>
<summary><strong>🧠 配置与易用性</strong></summary>

* **完全可配置**：所有默认值均由 `config.json` 控制
* **可调超时与限制**：精细控制重试、并发数与阈值
* **精简输出模式**：适合自动化与 Shell 管道

</details>

## 🚀 安装

### 系统要求

* 建议使用 [Python](http://python.org/downloads/) **3.8+**

### 克隆或下载

```bash
git clone https://github.com/BLACKGAMER1221/doh_tester.git
cd doh_tester
```

### 安装依赖

```bash
pip install requests dnspython
```

# 验证安装

```bash
python test_doh.py --help
```

## 使用方法与命令

### 基本用法

```bash
python test_doh.py <域名> [选项]
```

### 命令行参数

| 参数                  | 默认值           | 描述                        |
| ------------------- | ------------- | ------------------------- |
| `domain`            | (必填)          | 需要解析的域名（例如 `example.com`） |
| `--config`          | `config.json` | 配置文件路径                    |
| `--doh-file`        | `doh.txt`     | 包含 DoH URL 的文件路径          |
| `--timeout`         | `8.0`         | 每次操作超时时间（秒）               |
| `--workers`         | `20`          | 并行工作线程数                   |
| `--attempts`        | `3`           | 每个端点的 DNS 查询次数            |
| `--min-success`     | `2`           | 标记 WORKING 所需的最少成功次数      |
| `--insecure`        | `False`       | 跳过 TLS 证书验证               |
| `--output`          | (自动时间戳)       | 输出文件路径                    |
| `--working-only`    | `False`       | 仅显示 WORKING 结果            |
| `--no-working-only` | -             | 显示所有结果（覆盖配置）              |
| `--clean-output`    | `False`       | 仅输出可用 URL（每行一个）           |
| `--json-output`     | `False`       | 输出 JSON（自动时间戳或自定义路径）      |

### 使用示例

#### 基本测试

```bash
python test_doh.py example.com
```

#### 仅显示可用端点

```bash
python test_doh.py example.com --working-only
```

#### 精简输出（仅 URL 列表）

```bash
python test_doh.py example.com --clean-output
```

#### 自定义配置

```bash
python test_doh.py example.com \
  --doh-file my_doh_list.txt \
  --timeout 10 \
  --workers 30 \
  --attempts 5 \
  --min-success 3
```

#### JSON 输出

```bash
# 自动时间戳 JSON 文件名
python test_doh.py example.com --json-output

# 指定 JSON 文件名
python test_doh.py example.com --json-output results.json
```

#### 测试私有 DoH（自签名证书）

```bash
python test_doh.py internal.domain --insecure
```

#### 组合选项

```bash
python test_doh.py example.com --working-only --clean-output --json-output --output results.txt
```

---

## 配置文件

工具使用 JSON 配置文件（默认 `config.json`）来控制所有默认设置。

### 默认配置

```json
{
  "doh_file": "doh.txt",
  "output_file": "",
  "timeout": 8.0,
  "workers": 20,
  "attempts": 3,
  "min_success": 2,
  "remove_working_from_doh_file": false,
  "working_only": false,
  "json_output": false,
  "show_headers": true,
  "show_status": true,
  "show_doh_url": true,
  "show_host": true,
  "show_doh_ip": true,
  "show_target_ip": false,
  "show_ping": true
}
```

### 配置选项

#### 文件与输出设置

| 选项            | 类型     | 描述                |
| ------------- | ------ | ----------------- |
| `doh_file`    | string | 包含 DoH URL 的文件路径  |
| `output_file` | string | 默认输出文件（空 = 自动时间戳） |

#### 测试参数

| 选项            | 类型      | 描述                   |
| ------------- | ------- | -------------------- |
| `timeout`     | float   | 每次操作的超时时间（秒）         |
| `workers`     | integer | 并行测试线程数              |
| `attempts`    | integer | 每个端点的查询次数            |
| `min_success` | integer | 标记 WORKING 所需的最少成功次数 |

#### 文件管理

| 选项                             | 类型      | 描述                 |
| ------------------------------ | ------- | ------------------ |
| `remove_working_from_doh_file` | boolean | 从源文件中移除 WORKING 条目 |
| `working_only`                 | boolean | 默认仅显示 WORKING 结果   |

#### JSON 输出设置

| 选项            | 类型             | 描述                                             |
| ------------- | -------------- | ---------------------------------------------- |
| `json_output` | boolean/string | `false`（不输出 JSON）、`true`/`auto`（自动时间戳）、或自定义文件名 |

#### 显示设置

| 选项               | 类型      | 描述             |
| ---------------- | ------- | -------------- |
| `show_headers`   | boolean | 输出中显示列标题       |
| `show_status`    | boolean | 显示 STATUS 列    |
| `show_doh_url`   | boolean | 显示 URL 列       |
| `show_host`      | boolean | 显示 HOST 列      |
| `show_doh_ip`    | boolean | 显示 DOH_IP 列    |
| `show_target_ip` | boolean | 显示 TARGET_IP 列 |
| `show_ping`      | boolean | 显示 PING_MS 列   |

### DoH 文件格式

DoH URL 文件（默认 `doh.txt`）支持注释与空行：

```text
# 公共 DoH 服务器
https://cloudflare-dns.com/dns-query
https://dns.google/dns-query
https://dns.quad9.net/dns-query

# 私有/内部
https://doh.internal.company/dns-query
```

---

## 输出格式

### 标准文本输出

```
# Generated: 2026-02-4 08:50:45
STATUS    URL                                   HOST                DOH_IP           PING_MS
------------------------------------------------------------------------------------------------
WORKING   https://cloudflare-dns.com/dns-query  cloudflare-dns.com  104.16.249.249   45.2
WORKING   https://dns.google/dns-query          dns.google          8.8.8.8          32.1
BLOCKED   https://blocked.doh.server/dns-query  blocked.server      -                -
FLAKY     https://unreliable.doh/dns-query      unreliable.doh      192.0.2.1        120.5
```

### 精简输出

使用 `--clean-output` 时：

```
https://cloudflare-dns.com/dns-query
https://dns.google/dns-query
```

### JSON 输出

```json
[
  {
    "status": "WORKING",
    "url": "https://cloudflare-dns.com/dns-query",
    "host": "cloudflare-dns.com",
    "port": 443,
    "tcp_ok": true,
    "tls_ok": true,
    "tls_info": "cipher=('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)...",
    "successes": 3,
    "attempts": 3,
    "target_ips": "93.184.216.34",
    "doh_server_ip": "104.16.249.249",
    "method": "GET-wire",
    "latency_ms": "45.2",
    "notes": ""
  }
]
```

### 状态分类

| 状态          | 含义                                            |
| ----------- | --------------------------------------------- |
| **WORKING** | 端点通过所有测试（TCP、TLS，并且 DNS 查询成功次数 ≥ min_success） |
| **FLAKY**   | 端点部分可用（部分 DNS 查询成功，但少于 min_success）           |
| **BLOCKED** | 端点不可用（TCP/TLS 错误或没有成功 DNS 查询）                 |

---

## 提示与最佳实践

### 性能调优

1. **根据网络情况调整 workers 数量**：

   * 慢或不稳定网络：`--workers 5`
   * 快或稳定网络：`--workers 50`

2. **慢速网络可增加超时**：

   ```bash
   python test_doh.py example.com --timeout 15
   ```

3. **快速检测可减少尝试次数**：

   ```bash
   python test_doh.py example.com --attempts 1 --min-success 1
   ```

### 可靠性测试

1. **生产环境验证可使用更高尝试次数**：

   ```bash
   python test_doh.py example.com --attempts 5 --min-success 4
   ```

2. **测试多个域名**：

   ```bash
   for domain in example.com google.com cloudflare.com; do
     python test_doh.py $domain --json-output --output ${domain}.txt
   done
   ```

### 自动化

1. **定时监控任务（Cron）**：

   ```bash
   # 每天 3 点执行
   0 3 * * * cd /path/to/test_doh && python test_doh.py monitor.domain --json-output >> cron.log 2>&1
   ```

2. **生成精简列表脚本**：

   ```bash
   #!/bin/bash
   python test_doh.py example.com --clean-output --working-only --output working_doh.txt --json-output doh_results.json
   ```

### 故障排查

1. **所有端点 BLOCKED**：检查 ISP 或防火墙是否阻止 DoH
2. **TLS 失败**：自签名证书可尝试 `--insecure`
3. **超时**：增加 `--timeout` 或减少 `--workers`
4. **无结果**：确认 `doh.txt` 文件包含有效 URL

---

## 安全注意事项

* `--insecure` 标志会禁用 TLS 证书验证，仅用于测试私有服务器。
* DoH 查询是加密的，但目标服务器可以看到你的 DNS 查询。
* 建议对多个 DoH 提供商进行测试以提高冗余性。

---

## 许可证

MIT 许可证 - 详情见 LICENSE 文件。

---

## 贡献

欢迎贡献！请随时提交问题或 Pull Request。

---

## 致谢

* [RFC 8484](https://tools.ietf.org/html/rfc8484) - DNS Queries over HTTPS (DoH)
* [dnspython](https://www.dnspython.org/) - Python 的 DNS 工具包
* [requests](https://requests.readthedocs.io/) - Python HTTP 库
