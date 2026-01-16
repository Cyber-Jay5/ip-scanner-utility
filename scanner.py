import subprocess
import shutil
import threading
import queue
import re
import os
import sys
import requests
import whois
import netlas
import socket
from datetime import datetime
import time

class NmapScanner:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
        
        self.bundled_nmap = os.path.join(base_path, "nmap_bin", "nmap.exe")
        
        if os.path.exists(self.bundled_nmap):
            self.nmap_path = self.bundled_nmap
        else:
            self.nmap_path = shutil.which("nmap")

        self.process = None
        self.stop_event = threading.Event()

    def is_nmap_installed(self):
        return self.nmap_path is not None and os.path.exists(self.nmap_path)

    def build_command(self, target, scan_type, enable_traceroute):
        if not self.nmap_path:
            raise FileNotFoundError("Nmap not found.")

        cmd = [self.nmap_path, target]

        # Always add -Pn if traceroute is requested to ensure we try scanning 
        # even if ping fails (common firewall tactic).
        if enable_traceroute:
            cmd.append("-Pn")

        if scan_type == "Quick Scan":
            cmd.extend(["-T4", "-F"])
        elif scan_type == "Intense Scan":
            # Intense scan (-A) includes traceroute by default, but we'll be explicit
            # Also add -Pn to be aggressive against firewalls
            cmd.extend(["-T4", "-A", "-v", "-Pn"]) 
        elif scan_type == "Vulnerability Scan":
            cmd.extend(["-sV", "--script=vuln", "-Pn"])
        elif scan_type == "Ping Scan":
            cmd.extend(["-sn"])
            
        if enable_traceroute and "--traceroute" not in cmd and "-A" not in cmd:
            cmd.append("--traceroute")
        
        return cmd

    def get_geo_info(self, ip_or_domain):
        try:
            url = f"http://ip-api.com/json/{ip_or_domain}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
            return None
        except Exception:
            return None

    def get_whois_info(self, target):
        try:
            w = whois.whois(target)
            return w
        except Exception:
            return None

    def get_netlas_info(self, target, api_key):
        if not api_key:
            return None
        try:
            client = netlas.Netlas(api_key=api_key)
            response = client.host(target)
            return response
        except Exception as e:
            # Simplify error
            return {"error": "Authentication failed or Quota exceeded" if "40" in str(e) else str(e)}

    def get_http_headers(self, target):
        try:
            url = f"https://{target}"
            try:
                r = requests.head(url, timeout=3, allow_redirects=True, verify=False)
            except:
                url = f"http://{target}"
                r = requests.head(url, timeout=3, allow_redirects=True)
            
            return dict(r.headers)
        except requests.exceptions.Timeout:
            return {"error_msg": "Connection timed out (Host down or Firewall blocked)"}
        except requests.exceptions.ConnectionError:
             return {"error_msg": "Connection error (Service not reachable)"}
        except Exception as e:
            return {"error_msg": f"Failed: {str(e)}"}

    def get_ssh_banner(self, target):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, 22))
            banner = s.recv(1024)
            s.close()
            return banner.decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            return "Connection timed out (Port 22 filtered/closed)"
        except ConnectionRefusedError:
            return "Connection refused (Port 22 closed)"
        except Exception:
            return "Service not reachable"

    def run_batch_scan(self, targets, scan_type, include_geo_whois, netlas_api_key, enable_traceroute, output_callback, finished_callback):
        self.stop_event.clear()

        def _batch_process():
            combined_report = f"Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            combined_report += f"Scan Type: {scan_type}\n"
            combined_report += "="*50 + "\n\n"

            try:
                total_targets = len(targets)
                
                for i, target in enumerate(targets):
                    if self.stop_event.is_set():
                        break
                    
                    output_callback(f"\n[{i+1}/{total_targets}] Preparing to scan: {target}\n")
                    
                    target_result = self._scan_single_target(
                        target, scan_type, include_geo_whois, netlas_api_key, enable_traceroute, output_callback
                    )
                    
                    output_callback("\n" + target_result['summary'] + "\n")
                    
                    combined_report += target_result['summary'] + "\n"
                    combined_report += "[Raw Output Log]\n" + target_result['raw_output'] + "\n"
                    combined_report += "="*50 + "\n\n"

                if self.stop_event.is_set():
                    output_callback("\n[Batch Scan Cancelled]\n")
                    combined_report += "\n[Batch Scan Cancelled]"
                else:
                    output_callback(f"\n{'-'*40}\nAll Scans Completed.\n")

            except Exception as e:
                output_callback(f"\n[Error in batch process]: {e}\n")
                combined_report += f"\n[Error]: {e}"
            finally:
                finished_callback(combined_report)

        thread = threading.Thread(target=_batch_process, daemon=True)
        thread.start()

    def _scan_single_target(self, target, scan_type, include_geo, netlas_api_key, enable_traceroute, output_callback):
        
        extra_info = {}
        if include_geo and not self.stop_event.is_set():
            output_callback(f"Fetching Info for {target}...\n")
            geo = self.get_geo_info(target)
            if geo:
                extra_info['geo'] = geo
            
            try:
                w = self.get_whois_info(target)
                if w:
                    extra_info['whois'] = w
            except:
                pass
            
            output_callback(f"Checking HTTP Headers...\n")
            headers = self.get_http_headers(target)
            if headers:
                extra_info['http'] = headers

            output_callback(f"Checking SSH Banner...\n")
            banner = self.get_ssh_banner(target)
            extra_info['ssh'] = banner # Always set for report

        if netlas_api_key and not self.stop_event.is_set():
             output_callback(f"Querying Netlas...\n")
             n_info = self.get_netlas_info(target, netlas_api_key)
             if n_info:
                 extra_info['netlas'] = n_info

        # Run Nmap
        raw_output_list = []
        try:
            cmd = self.build_command(target, scan_type, enable_traceroute)
            
            creationflags = 0
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                creationflags = subprocess.CREATE_NO_WINDOW

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags
            )

            output_callback(f"Nmap Command: {' '.join(cmd)}\n")
            if self.nmap_path and "nmap_bin" in self.nmap_path:
                 output_callback(f"Using Bundled Nmap\n")
            output_callback(f"{'-'*40}\n")

            for line in self.process.stdout:
                if self.stop_event.is_set():
                    self.process.terminate()
                    break
                output_callback(line)
                raw_output_list.append(line)
            
            self.process.wait()
            self.process = None 

        except Exception as e:
            err = f"Error scanning {target}: {e}"
            output_callback(err + "\n")
            raw_output_list.append(err)

        raw_output = "".join(raw_output_list)
        
        summary = self.format_summary(target, scan_type, raw_output, extra_info)
        
        return {
            "target": target,
            "raw_output": raw_output,
            "summary": summary
        }

    def stop_scan(self):
        self.stop_event.set()
        if self.process:
            try:
                self.process.terminate()
            except:
                pass

    def format_summary(self, target, scan_type, raw_output, extra_info):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        open_ports = re.findall(r"(\d+/tcp)\s+open", raw_output)
        
        # Parse Traceroute
        traceroute_str = "No traceroute info."
        if "TRACEROUTE" in raw_output:
            # Extract the traceroute block
            match = re.search(r"(TRACEROUTE.*?)(?=\n\n|\Z)", raw_output, re.DOTALL)
            if match:
                traceroute_str = match.group(1)
        
        # Format Extra Info
        geo_str = "Not requested or not found."
        whois_str = "Not requested or not found."
        netlas_str = "Not requested or not found."
        http_str = "No headers found."
        ssh_str = "No SSH banner found."
        
        if 'geo' in extra_info:
            g = extra_info['geo']
            geo_str = f"""
    Internal IP: {g.get('query')}
    Country: {g.get('country')} ({g.get('countryCode')})
    Region: {g.get('regionName')}
    City: {g.get('city')}
    ISP: {g.get('isp')}
    Org: {g.get('org')}
    Timezone: {g.get('timezone')}
"""
        if 'whois' in extra_info:
            w = extra_info['whois']
            def clean(v):
                if isinstance(v, list):
                    return ', '.join([str(item) for item in v])
                return str(v)

            whois_str = f"""
    Registrar: {clean(w.registrar)}
    Creation Date: {clean(w.creation_date)}
    Expiration Date: {clean(w.expiration_date)}
    Emails: {clean(w.emails)}
"""

        if 'netlas' in extra_info:
            n = extra_info['netlas']
            if "error" in n:
                netlas_str = f"    Error: {n['error']}"
            else:
                ports = n.get("ports", [])
                vulns = n.get("vulnerabilities", [])
                passives = []
                if ports:
                    passives.append(f"Ports (Passive): {', '.join(map(str, ports))}")
                if vulns:
                    passives.append(f"Vulnerabilities: {len(vulns)} detected")
                netlas_str = "\n    ".join(passives) if passives else "    No additional data found."

        if 'http' in extra_info:
            h = extra_info['http']
            if "error_msg" in h:
                http_str = f"    {h['error_msg']}"
            elif "error" in h:
                http_str = f"    Error: {h['error']}"
            else:
                lines = []
                for k in ['Server', 'Date', 'Content-Type', 'X-Powered-By', 'Location']:
                    if k in h:
                        lines.append(f"{k}: {h[k]}")
                http_str = "\n    ".join(lines) if lines else "    Headers found but common fields missing."

        if 'ssh' in extra_info:
            ssh_str = f"    {extra_info['ssh']}"

        summary = f"""
--------------------------------------------------
TARGET SUMMARY: {target}
--------------------------------------------------
Scan Type: {scan_type}
Time:      {timestamp}

[Geo/Network]
{geo_str}

[Extended Probes]
HTTP (Curl):
{http_str}

SSH:
{ssh_str}

[WHOIS]
{whois_str}

[NETLAS]
{netlas_str}

[Ports & Trace (Nmap Active Scan)]
Open Ports: {len(open_ports)}
{', '.join(open_ports) if open_ports else "No open ports found (or check firewall)"}

[Traceroute]
{traceroute_str}
--------------------------------------------------
"""
        return summary
