# 🔒 DoH-Tester

🇺🇸 [English](README.md) | 🇷🇺 [Русский](README-RU.md) | 🇨🇳 [中文](README-ZH.md) | 🇮🇷 [فارسی](README-FA.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg  )](https://www.python.org/downloads/  )
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg  )](https://opensource.org/licenses/MIT  )
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg  )](https://github.com/psf/black  )

A high-performance, multi-threaded DNS-over-HTTPS (DoH) endpoint testing tool with intelligent protocol detection, configurable filtering, and automated list management.

## 📋 Introduction

DoH-Tester validates DoH endpoints at scale, testing TCP connectivity, TLS handshake, and actual DNS resolution across multiple protocols (Wire format GET/POST, JSON API). It's designed for network administrators, privacy advocates, and developers who need to maintain reliable, uncensored DNS resolution in hostile network environments.

---

### Key Features

- ✅ TCP connectivity testing (IPv4 & IPv6)
- 🔐 TLS handshake verification (optional insecure mode)
- 🌐 DNS resolution via:
  - DoH GET (wire format)
  - DoH POST (wire format)
  - DoH GET (JSON API)
- ⚡ Parallel testing using thread pools
- 🧠 Smart classification (WORKING / FLAKY / BLOCKED)
- 📊 Latency measurement (ms)
- 🧾 Human-readable table output
- 🧹 Clean output mode (URLs only)
- 📦 Optional JSON output (auto-timestamped or custom)
- 📁 Configurable via `config.json`
- 🗂 Optional automatic cleanup of working endpoints from source file

---

## 🎯 Use Cases

| Scenario | How DoH-Tester Helps |
|----------|---------------------|
| **Censorship Circumvention** | Quickly discover which DoH resolvers actually work to bypass DNS-based blocking and access filtered platforms |
| **Privacy Tool Maintenance** | Curate reliable DoH lists for VPNs, proxies, tunneling or browser configs |
| **Performance Optimization** | Measure latency to find fastest resolver for your location |
| **Network Auditing** | Validate DoH infrastructure across corporate/ISP networks |
| **Infrastructure Monitoring** | Automated health checks for private DoH servers |

<details>
<summary><b>🔓 Censorship Circumvention (Click to expand)</b></summary>

Connect to filtered platforms like YouTube, Instagram, Twitter/X, and news sites by resolving their domains through encrypted HTTPS connections, bypassing DNS-based filtering and DNS hijacking. [gfw resist HTTPS proxy](https://github.com/GFW-knocker/gfw_resist_HTTPS_proxy)

**How it works:**
- Standard DNS queries (UDP port 53) are unencrypted and easily intercepted by firewalls
- DoH encapsulates DNS queries within HTTPS traffic (port 443), making them indistinguishable from regular web browsing
- Useful on heavily censored networks where:
  - Standard DNS is poisoned (returning wrong IPs)
  - Domain names are blocked at the DNS resolver level
  - SNI filtering is employed but DNS encryption is not yet blocked

**Important Note:** for example, If VPNs or Cloudflare IPs are blocked at the **IP layer** (firewall drops packets to those IPs), DoH alone cannot restore access to those specific IPs. However, DoH can help you:
1. Discover working alternative endpoints not yet blocked
2. Resolve VPN domain names to IPs (if only DNS is blocked, not the VPN IPs themselves)
3. Access "domain-fronted" or alternate CDN endpoints that aren't IP-blocked
</details>

<details>
<summary><b>🔐 Privacy Tool Maintenance (Click to expand)</b></summary>

Maintain access to your privacy infrastructure when standard discovery mechanisms fail:

- **Access Blocked VPN Domains:** If your VPN provider's domain (e.g., `vpn-provider.com`) is blocked via DNS hijacking but their servers aren't IP-blocked, use working DoH endpoints to resolve the actual server addresses and maintain connectivity.

- **DNS Tunneling:** Use verified working DoH endpoints as transport layers for DNS tunneling tools like:
  - [dnstt](https://www.bamsoftware.com/software/dnstt/): TCP-over-DNS tunnel that works through DoH resolvers
  - [DNSCrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy): Can route through DoH with anonymized relays
  - [Iodine](https://github.com/yarrick/iodine): IP-over-DNS tunneling (requires UDP, but can use DoH for bootstrap)

- **Bootstrap Circumvention Tools:** Many anti-censorship tools (Tor bridges, Shadowsocks, WireGuard) require resolving a bootstrap server first. If that initial DNS lookup is poisoned, the tool can't connect. Pre-resolving via DoH provides the correct IPs to bootstrap your tools.
</details>

<details>
<summary><b>⚡ Performance Optimization (Click to expand)</b></summary>

Find the optimal resolver for your specific network conditions:
- Measure latency to multiple DoH endpoints simultaneously
- Identify geographic routing optimizations (some ISPs route to closer PoPs)
- Compare resolution speed between Wire format vs JSON API implementations
- Build location-aware resolver lists that auto-select the fastest option
</details>

<details>
<summary><b>🏢 Network Auditing (Click to expand)</b></summary>

Validate DoH infrastructure availability and compliance:
- Test which public DoH resolvers are accessible from corporate networks
- Verify that private/internal DoH servers are responding correctly
- Check for TLS interception (middleboxes breaking DoH connections)
- Generate compliance reports showing DNS privacy capability across network segments
</details>

## ✨ Full Function List

<details>
<summary><strong>🔍 Core Testing Capabilities</strong></summary>

* **DoH Protocol Support**: RFC 8484 DNS wire format via GET and POST, plus JSON API (Google / Cloudflare compatible)
* **Layered Validation**: TCP connectivity → TLS handshake → DoH application-level resolution
* **Smart Protocol Detection**: Automatically tests wire format and JSON API where applicable
* **Dual-Stack Networking**: IPv4 and IPv6 support with automatic fallback
* **ISP-Safe Testing**: Performs real DNS resolution without triggering DNS pollution or filtering

</details>

<details>
<summary><strong>⚡ Performance & Reliability</strong></summary>

* **Parallel Testing Engine**: Configurable thread pool for high-speed endpoint testing
* **Resilient Retry Logic**: Multiple attempts per endpoint with configurable success thresholds
* **Latency Measurement**: High-precision per-query timing in milliseconds
* **Safe Ctrl+C exit**: Graceful shutdown with partial results saved
* **Smart Classification**: Endpoints categorized as **WORKING**, **FLAKY**, or **BLOCKED**

</details>

<details>
<summary><strong>🔐 Security & Diagnostics</strong></summary>

* **TLS Validation**: Certificate and handshake verification with optional insecure mode
* **Certificate Inspection**: Captures TLS certificate subject and cipher details
* **Error Classification**: Distinguishes TCP blocks, TLS interception, and DoH application failures
* **Resolved IP Reporting**: Displays actual DNS resolution results for verification

</details>

<details>
<summary><strong>📊 Output & Reporting</strong></summary>

* **Flexible Output Formats**:

  * Human-readable tables
  * Clean URL-only lists (script-friendly)
  * Machine-readable JSON
* **Timestamped Outputs**: Automatic ISO 8601 timestamps (or custom filenames)
* **Sorted Results**: JSON output sorted by latency (fastest first)
* **Working-Only Filters**: Option to display or export only functional endpoints

</details>

<details>
<summary><strong>🗂 List & File Management</strong></summary>

* **Automatic Cleanup Mode**: Remove working endpoints from the source list
* **Backup Protection**: Creates `.backup` files before modifying inputs
* **Comment Preservation**: Retains comments and formatting in endpoint lists
* **Self-Healing Lists**: Helps maintain fresh, reliable DoH endpoint collections

</details>

<details>
<summary><strong>🧠 Configuration & Usability</strong></summary>

* **Fully Configurable**: All defaults controlled via `config.json`
* **Adjustable Timeouts & Limits**: Fine-tuned control for retries, workers, and thresholds
* **Clean Output Mode**: Minimal output for automation and shell pipelines

</details>



## 🚀 Installation

### Requirements

* [Python](http://python.org/downloads/) **3.8+** recommended

### Clone or Download

```bash
git clone https://github.com/BLACKGAMER1221/doh_tester.git
cd doh_tester
```

### Install Dependencies

```bash
pip install requests dnspython
```


# Verify installation

```bash
python test_doh.py --help
```

## Usage and Commands

### Basic Usage

```bash
python test_doh.py <domain> [options]
```

### Command-Line Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `domain` | (required) | Domain to resolve (e.g., `example.com`) |
| `--config` | `config.json` | Path to configuration file |
| `--doh-file` | `doh.txt` | Path to file containing DoH URLs |
| `--timeout` | `8.0` | Timeout per operation in seconds |
| `--workers` | `20` | Number of parallel worker threads |
| `--attempts` | `3` | DNS query attempts per endpoint |
| `--min-success` | `2` | Minimum successful replies to mark WORKING |
| `--insecure` | `False` | Skip TLS certificate verification |
| `--output` | (timestamped) | Output file path |
| `--working-only` | `False` | Show only WORKING results |
| `--no-working-only` | - | Show all results (override config) |
| `--clean-output` | `False` | Output only working URLs (one per line) |
| `--json-output` | `False` | Write JSON output (auto-timestamp or specify path) |

### Usage Examples

#### Basic Test

```bash
python test_doh.py example.com
```

#### Show Only Working Endpoints

```bash
python test_doh.py example.com --working-only
```

#### Clean Output (URL List Only)

```bash
python test_doh.py example.com --clean-output
```

#### Custom Configuration

```bash
python test_doh.py example.com \
  --doh-file my_doh_list.txt \
  --timeout 10 \
  --workers 30 \
  --attempts 5 \
  --min-success 3
```

#### JSON Output

```bash
# Auto-timestamped JSON filename
python test_doh.py example.com --json-output

# Specific JSON filename
python test_doh.py example.com --json-output results.json
```

#### Test Private DoH (Self-Signed Certs)

```bash
python test_doh.py internal.domain --insecure
```

#### Combined Options

```bash
python test_doh.py example.com --working-only --clean-output --json-output --output results.txt
```

---

## Configuration File

The tool uses a JSON configuration file (`config.json` by default) to control all default settings.

### Default Configuration

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

### Configuration Options

#### File and Output Settings

| Option | Type | Description |
|--------|------|-------------|
| `doh_file` | string | Path to file containing DoH URLs |
| `output_file` | string | Default output file (empty = timestamped) |

#### Testing Parameters

| Option | Type | Description |
|--------|------|-------------|
| `timeout` | float | Seconds per operation timeout |
| `workers` | integer | Parallel testing threads |
| `attempts` | integer | Query attempts per endpoint |
| `min_success` | integer | Minimum successes for WORKING status |

#### File Management

| Option | Type | Description |
|--------|------|-------------|
| `remove_working_from_doh_file` | boolean | Remove WORKING entries from source file |
| `working_only` | boolean | Default to showing only WORKING results |

#### JSON Output Settings

| Option | Type | Description |
|--------|------|-------------|
| `json_output` | boolean/string | `false` (no JSON), `true`/`"auto"` (timestamped), or filename |

#### Display Settings

| Option | Type | Description |
|--------|------|-------------|
| `show_headers` | boolean | Show column headers in output |
| `show_status` | boolean | Show STATUS column |
| `show_doh_url` | boolean | Show URL column |
| `show_host` | boolean | Show HOST column |
| `show_doh_ip` | boolean | Show DOH_IP column |
| `show_target_ip` | boolean | Show TARGET_IP column |
| `show_ping` | boolean | Show PING_MS column |

### DoH File Format

The DoH URL file (`doh.txt` by default) supports comments and empty lines:

```text
# Public DoH Servers
https://cloudflare-dns.com/dns-query
https://dns.google/dns-query
https://dns.quad9.net/dns-query

# Private/Internal
https://doh.internal.company/dns-query
```

---

## Output Formats

### Standard Text Output

```
# Generated: 2026-02-4 08:50:45
STATUS    URL                                   HOST                DOH_IP           PING_MS
------------------------------------------------------------------------------------------------
WORKING   https://cloudflare-dns.com/dns-query  cloudflare-dns.com  104.16.249.249   45.2
WORKING   https://dns.google/dns-query          dns.google          8.8.8.8          32.1
BLOCKED   https://blocked.doh.server/dns-query  blocked.server      -                -
FLAKY     https://unreliable.doh/dns-query      unreliable.doh      192.0.2.1        120.5
```

### Clean Output

When using `--clean-output`:

```
https://cloudflare-dns.com/dns-query
https://dns.google/dns-query
```

### JSON Output

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

### Status Classifications

| Status | Meaning |
|--------|---------|
| **WORKING** | Endpoint passed all tests (TCP, TLS, and greater than or equal min_success DNS queries) |
| **FLAKY** | Endpoint partially works (some DNS queries succeeded but less than min_success) |
| **BLOCKED** | Endpoint failed (TCP/TLS error or no successful DNS queries) |

---

## Tips and Best Practices

### Performance Tuning

1. **Adjust workers based on your connection**: 
   - Slow/unstable: `--workers 5`
   - Fast/stable: `--workers 50`

2. **Increase timeout for slow networks**:
   ```bash
   python test_doh.py example.com --timeout 15
   ```

3. **Reduce attempts for quick checks**:
   ```bash
   python test_doh.py example.com --attempts 1 --min-success 1
   ```

### Reliability Testing

1. **Use higher attempts for production validation**:
   ```bash
   python test_doh.py example.com --attempts 5 --min-success 4
   ```

2. **Test multiple domains**:
   ```bash
   for domain in example.com google.com cloudflare.com; do
     python test_doh.py $domain --json-output --output ${domain}.txt
   done
   ```

### Automation

1. **Cron job for monitoring**:
   ```bash
   # Run daily at 3 AM
   0 3 * * * cd /path/to/test_doh && python test_doh.py monitor.domain --json-output >> cron.log 2>&1
   ```

2. **Script for generating clean lists**:
   ```bash
   #!/bin/bash
   python test_doh.py example.com --clean-output --working-only --output working_doh.txt --json-output doh_results.json
   ```

### Troubleshooting

1. **All endpoints BLOCKED**: Check if DoH is blocked by your ISP or firewall
2. **TLS failures**: Try `--insecure` for self-signed certificates
3. **Timeouts**: Increase `--timeout` or reduce `--workers`
4. **No results**: Verify your `doh.txt` file contains valid URLs

---

## Security Considerations

- The `--insecure` flag disables TLS certificate verification. Use only for testing private servers.
- DoH queries are encrypted but the destination server can see your DNS queries.
- Consider running tests against multiple DoH providers for redundancy.

---

## License

MIT License - See LICENSE file for details.

---

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## Acknowledgments

- [RFC 8484](https://tools.ietf.org/html/rfc8484) - DNS Queries over HTTPS (DoH)
- [dnspython](https://www.dnspython.org/) - DNS toolkit for Python
- [requests](https://requests.readthedocs.io/) - HTTP library for Python
