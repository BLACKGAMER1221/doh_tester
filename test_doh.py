#!/usr/bin/env python3
"""
https://github.com/BLACKGAMER1221/doh_tester

test_doh.py

Install requirements:
    pip install requests dnspython

Usage examples:
    python test_doh.py example.com
    python test_doh.py example.com --working-only
    python test_doh.py example.com --clean-output
    python test_doh.py example.com --config myconfig.json

Config file (config.json) controls all defaults:
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

Note: 
- output_file empty string "" means use timestamped naming (empty by default)
- json_output can be: false (no json), true/"auto" (timestamped), or a specific filename string
"""
from __future__ import annotations
import argparse
import base64
import socket
import ssl
import time
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from pathlib import Path
import threading
import sys
import signal

import requests
import dns.message
import dns.rdatatype

# Global flag for graceful shutdown
shutdown_requested = threading.Event()

def timestamped_json_name():
    return time.strftime("%Y-%m-%dT%H-%M-%S") + ".json"

def timestamped_txt_name():
    return time.strftime("%Y-%m-%dT%H-%M-%S") + ".txt"

def load_config(path: str = "config.json"):
    """
    Load configuration from JSON file.
    Creates default config if file doesn't exist.
    """
    default_config = {
        # File and output settings
        "doh_file": "doh.txt",
        "output_file": "",
        # Testing parameters
        "timeout": 8.0,
        "workers": 20,
        "attempts": 3,
        "min_success": 2,
        # File management
        "remove_working_from_doh_file": False,
        "working_only": False,
        # JSON output settings
        "json_output": False,  # Can be: false, true/"auto", or a specific filename string
        # Display settings
        "show_headers": True,
        "show_status": True,
        "show_doh_url": True,
        "show_host": True,
        "show_doh_ip": True,
        "show_target_ip": False,
        "show_ping": True
    }
    
    config_path = Path(path)
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                default_config.update(user_config)
                print(f"Loaded config from {config_path}")
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {config_path}, using defaults. Error: {e}")
        except Exception as e:
            print(f"Warning: Could not read {config_path}, using defaults. Error: {e}")
    else:
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=2)
            print(f"Created default config file: {config_path}")
        except Exception as e:
            print(f"Note: Could not create default config file: {e}")
    
    return default_config

def remove_working_from_file(doh_file_path: str, results: list, backup_suffix: str = ".backup"):
    """
    Remove WORKING entries from the DoH file.
    Creates a backup before modifying.
    Preserves comments and empty lines that aren't associated with working URLs.
    """
    file_path = Path(doh_file_path)
    
    if not file_path.exists():
        print(f"Warning: Cannot remove working entries - file not found: {file_path}")
        return False
    
    # Create set of working URLs (normalized)
    working_urls = {r["url"].strip() for r in results if r["status"] == "WORKING"}
    
    if not working_urls:
        print("No WORKING entries found to remove from doh file")
        return False
    
    # Read original file
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading doh file for cleanup: {e}")
        return False
    
    # Filter lines: keep comments, empty lines, and non-working URLs
    filtered_lines = []
    removed_count = 0
    
    for line in lines:
        stripped = line.strip()
        
        # Keep comments and empty lines
        if not stripped or stripped.startswith("#"):
            filtered_lines.append(line)
            continue
            
        # Check if this URL is in working set
        if stripped in working_urls:
            removed_count += 1
            continue  # Skip this line (remove it)
        else:
            filtered_lines.append(line)
    
    if removed_count == 0:
        print("No WORKING URLs found in doh file to remove")
        return False
    
    # Create backup
    backup_path = file_path.with_suffix(file_path.suffix + backup_suffix)
    try:
        shutil.copy2(file_path, backup_path)
        print(f"Created backup: {backup_path}")
    except Exception as e:
        print(f"Warning: Failed to create backup: {e}")
        return False
    
    # Write filtered content back
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(filtered_lines)
        print(f"Removed {removed_count} WORKING entries from {file_path}")
        print(f"Kept {len(filtered_lines) - removed_count} lines (including comments/empty)")
        return True
    except Exception as e:
        print(f"Error writing filtered doh file: {e}")
        # Try to restore backup
        try:
            shutil.copy2(backup_path, file_path)
            print("Restored original file from backup due to error")
        except:
            pass
        return False

def load_doh_list(path: str):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out

def parse_host_port_from_url(url: str):
    p = urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme in ("https",) else 443)
    return host, port

def tcp_connect(host: str, port: int, timeout: float):
    """
    Attempt TCP connection and return (success, ip_used, error_message).
    ip_used is the actual IP address connected to (IPv4 or IPv6).
    """
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, None, "DNS resolution returned no addresses"
        
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_address = sockaddr[0]
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                sock.close()
                return True, ip_address, None
            except socket.error:
                continue
        
        return False, None, "Failed to connect to any resolved IP"
    except socket.gaierror as e:
        return False, None, f"DNS resolution failed: {e}"
    except Exception as e:
        return False, None, str(e)

def tls_handshake(host: str, port: int, timeout: float, verify: bool):
    try:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        ss = ctx.wrap_socket(sock, server_hostname=host if verify else None)
        cert = ss.getpeercert()
        cipher = ss.cipher()
        ss.close()
        subj = None
        if isinstance(cert, dict):
            subj = cert.get('subject')
        info = f"cipher={cipher}, cert_subject={subj}"
        return True, info
    except Exception as e:
        return False, str(e)

def make_wire_query(domain: str):
    q = dns.message.make_query(domain, 'A')
    return q.to_wire()

def base64url_no_pad(b: bytes):
    s = base64.urlsafe_b64encode(b).decode('ascii')
    return s.rstrip('=')

def try_get_wire(session: requests.Session, doh_url: str, query_wire: bytes, timeout: float, verify: bool):
    sep = '&' if ('?' in doh_url) else '?'
    url = doh_url + sep + 'dns=' + base64url_no_pad(query_wire)
    headers = {'accept': 'application/dns-message', 'user-agent': 'doh_tester/1.2'}
    t0 = time.perf_counter()
    try:
        r = session.get(url, headers=headers, timeout=timeout, verify=verify)
        latency = (time.perf_counter() - t0) * 1000.0
        if r.status_code == 200 and 'dns-message' in (r.headers.get('content-type') or ''):
            try:
                msg = dns.message.from_wire(r.content)
                ips = []
                for ans in msg.answer:
                    if ans.rdtype == dns.rdatatype.A:
                        for item in ans:
                            ips.append(item.address)
                if ips:
                    return True, ips, latency, 'GET-wire', r.status_code
            except Exception:
                return False, None, latency, 'GET-wire-parse-fail', r.status_code
        return False, None, latency, f'GET-wire-{r.status_code}', r.status_code
    except Exception as e:
        return False, None, None, f'GET-wire-exc:{e}', None

def try_post_wire(session: requests.Session, doh_url: str, query_wire: bytes, timeout: float, verify: bool):
    headers = {'accept': 'application/dns-message', 'content-type': 'application/dns-message', 'user-agent': 'doh_tester/1.2'}
    t0 = time.perf_counter()
    try:
        r = session.post(doh_url, headers=headers, data=query_wire, timeout=timeout, verify=verify)
        latency = (time.perf_counter() - t0) * 1000.0
        if r.status_code == 200 and 'dns-message' in (r.headers.get('content-type') or ''):
            try:
                msg = dns.message.from_wire(r.content)
                ips = []
                for ans in msg.answer:
                    if ans.rdtype == dns.rdatatype.A:
                        for item in ans:
                            ips.append(item.address)
                if ips:
                    return True, ips, latency, 'POST-wire', r.status_code
            except Exception:
                return False, None, latency, 'POST-wire-parse-fail', r.status_code
        return False, None, latency, f'POST-wire-{r.status_code}', r.status_code
    except Exception as e:
        return False, None, None, f'POST-wire-exc:{e}', None

def try_get_json(session: requests.Session, doh_url: str, domain: str, timeout: float, verify: bool):
    t0 = time.perf_counter()
    try:
        params = {'name': domain, 'type': 'A'}
        r = session.get(doh_url, params=params, timeout=timeout, verify=verify, headers={'accept': 'application/dns-json', 'user-agent': 'doh_tester/1.2'})
        latency = (time.perf_counter() - t0) * 1000.0
        if r.status_code == 200 and ('json' in (r.headers.get('content-type') or '')):
            try:
                j = r.json()
                ips = []
                for ans in j.get('Answer', []) or []:
                    if isinstance(ans, dict) and int(ans.get('type', 0)) == 1:
                        data = ans.get('data')
                        if data:
                            ips.append(data)
                if ips:
                    return True, ips, latency, 'GET-json', r.status_code
            except Exception:
                return False, None, latency, 'GET-json-parse-fail', r.status_code
        return False, None, latency, f'GET-json-{r.status_code}', r.status_code
    except Exception as e:
        return False, None, None, f'GET-json-exc:{e}', None

def single_query_try(session, doh_url, domain, timeout, verify):
    query_wire = make_wire_query(domain)
    ok, ips, latency, method, status = try_get_wire(session, doh_url, query_wire, timeout, verify)
    if ok:
        return True, ips, latency, method, status
    ok, ips, latency, method, status = try_post_wire(session, doh_url, query_wire, timeout, verify)
    if ok:
        return True, ips, latency, method, status
    ok, ips, latency, method, status = try_get_json(session, doh_url, domain, timeout, verify)
    if ok:
        return True, ips, latency, method, status
    return False, None, latency, method, status

def test_endpoint(doh_url: str, domain: str, timeout: float, attempts: int, min_success: int, verify: bool):
    # Check if shutdown was requested before starting
    if shutdown_requested.is_set():
        return {
            "status": "INTERRUPTED",
            "url": doh_url,
            "host": parse_host_port_from_url(doh_url)[0],
            "port": parse_host_port_from_url(doh_url)[1],
            "tcp_ok": False,
            "tls_ok": False,
            "tls_info": None,
            "doh_server_ip": None,
            "successes": 0,
            "attempts": 0,
            "last_ips": None,
            "last_method": None,
            "last_latency_ms": None,
            "notes": ["interrupted_before_testing"],
        }
    
    host, port = parse_host_port_from_url(doh_url)
    result = {
        "url": doh_url,
        "host": host,
        "port": port,
        "tcp_ok": False,
        "tls_ok": False,
        "tls_info": None,
        "doh_server_ip": None,
        "successes": 0,
        "attempts": attempts,
        "last_ips": None,
        "last_method": None,
        "last_latency_ms": None,
        "notes": [],
    }

    tcp_ok, doh_ip, tcp_err = tcp_connect(host, port, timeout)
    result["tcp_ok"] = tcp_ok
    result["doh_server_ip"] = doh_ip
    
    if not tcp_ok:
        result["notes"].append(f"tcp_connect_failed:{tcp_err}")
        return classify_result(result, blocked_reason="tcp")

    tls_ok, tls_info = tls_handshake(host, port, timeout, verify)
    result["tls_ok"] = tls_ok
    result["tls_info"] = tls_info
    if not tls_ok:
        result["notes"].append(f"tls_handshake_failed:{tls_info}")
        return classify_result(result, blocked_reason="tls")

    session = requests.Session()
    success_count = 0
    last_ips = None
    last_method = None
    last_latency = None
    for i in range(attempts):
        # Check for shutdown between attempts
        if shutdown_requested.is_set():
            result["notes"].append(f"interrupted_at_attempt{i+1}")
            break
            
        ok, ips, latency, method, status = single_query_try(session, doh_url, domain, timeout, verify)
        if ok:
            success_count += 1
            last_ips = ips
            last_method = method
            last_latency = latency
        else:
            result["notes"].append(f"attempt{i+1}:{method}:{status}")
    result["successes"] = success_count
    result["last_ips"] = last_ips
    result["last_method"] = last_method
    result["last_latency_ms"] = last_latency

    if shutdown_requested.is_set():
        return classify_result(result, blocked_reason="interrupted")
    elif success_count >= min_success:
        return classify_result(result, blocked_reason=None)
    elif success_count > 0:
        return classify_result(result, blocked_reason="flaky")
    else:
        result["notes"].append("tls_ok_but_no_doh_answers")
        return classify_result(result, blocked_reason="no_answers")

def classify_result(result: dict, blocked_reason: str|None):
    if blocked_reason is None:
        status = "WORKING"
    elif blocked_reason == "flaky":
        status = "FLAKY"
    elif blocked_reason == "interrupted":
        status = "INTERRUPTED"
    else:
        status = "BLOCKED"
    
    out = {
        "status": status,
        "url": result.get("url"),
        "host": result.get("host"),
        "port": result.get("port"),
        "tcp_ok": result.get("tcp_ok"),
        "tls_ok": result.get("tls_ok"),
        "tls_info": result.get("tls_info"),
        "successes": result.get("successes"),
        "attempts": result.get("attempts"),
        "target_ips": ",".join(result["last_ips"]) if result.get("last_ips") else "",
        "doh_server_ip": result.get("doh_server_ip") or "",
        "method": result.get("last_method") or "",
        "latency_ms": (f"{result.get('last_latency_ms'):.1f}" if result.get('last_latency_ms') else ""),
        "notes": ";".join(result.get("notes") or []),
    }
    return out

def write_text_output(results, out_path, config, working_only=False, clean_output=False):
    """Write text output with various formatting options."""
    
    # Handle clean output: only working URLs, one per line, nothing else
    if clean_output:
        with out_path.open("w", encoding="utf-8") as outf:
            for r in results:
                if r["status"] == "WORKING":
                    outf.write(r["url"] + "\n")
        return
    
    # Define column specifications: (config_key, header, result_key)
    col_specs = []
    if config.get("show_status", True):
        col_specs.append(("status", "STATUS", "status"))
    if config.get("show_doh_url", True):
        col_specs.append(("url", "URL", "url"))
    if config.get("show_host", True):
        col_specs.append(("host", "HOST", "host"))
    if config.get("show_doh_ip", True):
        col_specs.append(("doh_ip", "DOH_IP", "doh_server_ip"))
    if config.get("show_target_ip", True):
        col_specs.append(("target", "TARGET_IP", "target_ips"))
    if config.get("show_ping", True):
        col_specs.append(("ping", "PING_MS", "latency_ms"))
    
    if not col_specs:
        with out_path.open("w", encoding="utf-8") as outf:
            outf.write("# No columns enabled in config\n")
        return
    
    # Filter results if working_only
    display_results = [r for r in results if not working_only or r["status"] == "WORKING"]
    
    if not display_results:
        with out_path.open("w", encoding="utf-8") as outf:
            outf.write("# No results to display\n")
        return
    
    # Calculate column widths: max of header length and max data length, plus 2 spaces padding
    widths = {}
    for config_key, header, result_key in col_specs:
        header_len = len(header)
        max_data_len = max(len(str(r.get(result_key, ""))) for r in display_results)
        widths[result_key] = max(header_len, max_data_len) + 2  # +2 for spacing
    
    lines = []
    
    # Add headers only if show_headers is True
    if config.get("show_headers", True):
        lines.append(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        header_parts = []
        for config_key, header, result_key in col_specs:
            header_parts.append(f"{header:<{widths[result_key]}}")
        header_line = "".join(header_parts).rstrip()
        lines.append(header_line)
        lines.append("-" * len(header_line))
    
    # Add data rows with alignment
    for r in display_results:
        row_parts = []
        for config_key, header, result_key in col_specs:
            value = str(r.get(result_key, ""))
            row_parts.append(f"{value:<{widths[result_key]}}")
        lines.append("".join(row_parts).rstrip())
    
    with out_path.open("w", encoding="utf-8") as outf:
        outf.write("\n".join(lines))
        if lines:
            outf.write("\n")

def resolve_json_output_config(args_json_output, config_json_output):
    """
    Determine if JSON output should be enabled and what path to use.
    Priority: command line args > config > default (None)
    Returns: (should_output_json, json_path_or_none)
    """
    # Command line argument provided
    if args_json_output is not None:
        if args_json_output == "__AUTO__":
            return True, None  # Use auto timestamp
        else:
            return True, args_json_output  # Use specific path
    
    # Check config
    if config_json_output:
        if isinstance(config_json_output, bool) and config_json_output:
            return True, None  # Auto timestamp from config
        elif isinstance(config_json_output, str):
            if config_json_output.lower() in ("true", "auto", "1"):
                return True, None  # Auto timestamp
            else:
                return True, config_json_output  # Specific path
    
    # Default: no JSON output
    return False, None

def save_results(results, out_path, config, args, should_output_json, explicit_json_path, interrupted=False):
    """Save results to text and optionally JSON files."""
    
    # Write text output
    write_text_output(results, out_path, config, working_only=args.working_only, clean_output=args.clean_output)
    
    # Handle JSON output
    if should_output_json:
        if explicit_json_path:
            json_path = Path(explicit_json_path)
        else:
            json_path = Path(timestamped_json_name())
        
        to_dump = [r for r in results if not args.working_only or r["status"] == "WORKING"]
        
        def latency_key(item):
            v = item.get("latency_ms")
            if not v:
                return float("inf")
            try:
                return float(v)
            except Exception:
                return float("inf")

        to_dump_sorted = sorted(to_dump, key=latency_key)
        
        try:
            with json_path.open("w", encoding="utf-8") as jf:
                json.dump(to_dump_sorted, jf, indent=2, ensure_ascii=False, default=str)
            
            filter_msg = "WORKING only" if args.working_only else "all statuses"
            source_msg = " [cmd]" if args.json_output is not None else " [cfg]"
            interrupt_msg = " [INTERRUPTED]" if interrupted else ""
            print(f"\nJSON results written to {json_path.resolve()} ({filter_msg}){source_msg}{interrupt_msg}")
        except Exception as e:
            print(f"\nFailed to write JSON output to {json_path}: {e}")

def print_summary(results, out_path, args, should_output_json, config):
    """Print final summary statistics."""
    working = sum(1 for r in results if r["status"]=="WORKING")
    flaky = sum(1 for r in results if r["status"]=="FLAKY")
    blocked = sum(1 for r in results if r["status"]=="BLOCKED")
    interrupted = sum(1 for r in results if r["status"]=="INTERRUPTED")
    
    if args.clean_output:
        output_mode = "clean URLs only"
    elif args.working_only:
        output_mode = "working-only with columns"
    else:
        output_mode = "full details"
    
    json_status = "JSON enabled" if should_output_json else "no JSON"
    if should_output_json and args.working_only:
        json_status += " (filtered)"
    
    interrupt_str = f", INTERRUPTED={interrupted}" if interrupted > 0 else ""
    print(f"Done. Results saved to {out_path.resolve()}. WORKING={working}, FLAKY={flaky}, BLOCKED={blocked}{interrupt_str}")

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    if not shutdown_requested.is_set():
        print("\n\n⚠️  Shutdown requested (Ctrl+C)... finishing current tests and saving results...")
        shutdown_requested.set()
    else:
        print("\n⚠️  Forcing immediate exit...")
        sys.exit(1)

def main():
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Pre-parse to get config file path
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", default="config.json")
    pre_args, remaining_argv = pre_parser.parse_known_args()
    
    # Load config
    config = load_config(pre_args.config)
    
    # Determine output file default (timestamped if config has empty string)
    config_output = config.get("output_file", "")
    if config_output == "":
        default_output = timestamped_txt_name()
    else:
        default_output = config_output
    
    # Main parser with config-based defaults
    p = argparse.ArgumentParser(description="ISP-safe DoH tester with configurable defaults")
    p.add_argument("domain", help="Domain to resolve (e.g. example.com)")
    p.add_argument("--config", default="config.json", help="Path to config.json (default: config.json)")
    p.add_argument("--doh-file", default=config.get("doh_file", "doh.txt"), help=f"Path to doh.txt (config default: {config.get('doh_file', 'doh.txt')})")
    p.add_argument("--timeout", type=float, default=config.get("timeout", 8.0), help=f"Per-operation timeout seconds (config default: {config.get('timeout', 8.0)})")
    p.add_argument("--workers", type=int, default=config.get("workers", 20), help=f"Parallel worker threads (config default: {config.get('workers', 20)})")
    p.add_argument("--attempts", type=int, default=config.get("attempts", 3), help=f"How many query attempts per DoH (config default: {config.get('attempts', 3)})")
    p.add_argument("--min-success", type=int, default=config.get("min_success", 2), help=f"Min successful replies to mark WORKING (config default: {config.get('min_success', 2)})")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification (useful for private DoH)")
    p.add_argument("--output", default=default_output, help=f"Output file (config default: {'timestamped' if config_output == '' else config_output})")
    p.add_argument("--working-only", action="store_true", default=config.get("working_only", False), help=f"Filter to show only WORKING results in both text and JSON output (config default: {config.get('working_only', False)})")
    p.add_argument("--no-working-only", dest="working_only", action="store_false", help="Show all results regardless of status (override config)")
    p.add_argument("--clean-output", action="store_true", help="Output only working DoH URLs (one per line) in result.txt. Overrides column settings.")
    p.add_argument("--json-output", nargs='?', const="__AUTO__", default=None, help="Write JSON output. Overrides config. Optionally provide a path (or use 'auto'/no value for timestamp).")
    args = p.parse_args(remaining_argv)

    # Show effective settings
    print(f"Settings: timeout={args.timeout}s, workers={args.workers}, attempts={args.attempts}, min_success={args.min_success}")
    
    # Show file cleanup setting
    if config.get("remove_working_from_doh_file", False):
        print("⚠️  File cleanup ENABLED: WORKING entries will be removed from doh file after testing")
    
    # Show JSON output status
    should_json, json_path_override = resolve_json_output_config(args.json_output, config.get("json_output", False))
    if should_json:
        json_mode_str = "ENABLED (timestamped)" if json_path_override is None else f"ENABLED (path: {json_path_override})"
        if args.json_output is not None:
            json_mode_str += " [from command line]"
        else:
            json_mode_str += " [from config]"
        print(f"JSON output {json_mode_str}")
    
    # Show which columns/headers are enabled (irrelevant for clean output)
    if not args.clean_output:
        enabled = [k.replace("show_", "") for k, v in config.items() if v and k.startswith("show_")]
        print(f"Display columns: {', '.join(enabled)}")

    doh_path = Path(args.doh_file)
    if not doh_path.exists():
        print("doh file not found:", doh_path)
        sys.exit(2)

    doh_list = load_doh_list(str(doh_path))
    if not doh_list:
        print("No DoH endpoints found in", doh_path)
        sys.exit(1)

    print(f"Testing {len(doh_list)} DoH endpoints for domain {args.domain} (verify_tls={not args.insecure})")

    results = []
    lock = threading.Lock()
    interrupted = False
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(test_endpoint, doh, args.domain, args.timeout, args.attempts, args.min_success, not args.insecure): doh for doh in doh_list}
            for fut in as_completed(futures):
                doh = futures[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"status": "BLOCKED", "url": doh, "host": "", "port": "", "tcp_ok": False, "tls_ok": False, "tls_info":str(e), "successes":0, "attempts":args.attempts, "target_ips":"", "doh_server_ip":"", "method":"exception", "latency_ms":"", "notes":f"exception:{e}"}
                with lock:
                    results.append(r)
                    # Console output shows key info for real-time monitoring
                    if r["status"] == "WORKING":
                        print(f"[WORKING] {r['url']} | DoH_IP:{r['doh_server_ip']} | Target:{r['target_ips']} | {r['latency_ms']}ms")
                    elif r["status"] == "FLAKY":
                        print(f"[FLAKY]   {r['url']} | successes={r['successes']}/{r['attempts']}")
                    elif r["status"] == "INTERRUPTED":
                        print(f"[INTERRUPTED] {r['url']} | stopped early")
                    else:
                        print(f"[BLOCKED] {r['url']} | {r['notes'][:60]}")
                
                # Check if shutdown was requested
                if shutdown_requested.is_set():
                    interrupted = True
                    # Cancel remaining futures
                    for future in futures:
                        if not future.done():
                            future.cancel()
                    break
    except Exception as e:
        print(f"\nError during testing: {e}")
        interrupted = True

    out_path = Path(args.output)
    
    # Save results (handles both normal and interrupted cases)
    save_results(results, out_path, config, args, should_json, json_path_override, interrupted=interrupted)

    # Optional: Remove WORKING entries from doh file (only if not interrupted)
    if not interrupted and config.get("remove_working_from_doh_file", False):
        print("\n--- File Cleanup ---")
        remove_working_from_file(args.doh_file, results)

    # Print final summary
    print_summary(results, out_path, args, should_json, config)

if __name__ == "__main__":
    main()