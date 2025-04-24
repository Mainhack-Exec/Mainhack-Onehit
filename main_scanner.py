#!/usr/bin/env python3

import subprocess
import argparse
import os
import sys
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import shlex

# --- Configuration ---
# Make sure these paths are correct relative to where you run the script
SUBFINDER_SCRIPT = os.path.join('subfinder', 'main.py')
SQLI_PAYLOADS = os.path.join('payload', 'SQL Injection (SQLi) Payloads.txt')
XSS_PAYLOADS = os.path.join('payload', 'Cross-Site Scripting (XSS) Payloads.txt')
LFI_PAYLOADS = os.path.join('payload', 'Local File Inclusion (LFI) Payloads.txt')
# Assumed commands/scripts for the tools
WAYBACKURLS_CMD = "waybackurls" # Assumes waybackurls is in PATH
SQLMAP_CMD = "sqlmap"           # Assumes sqlmap is in PATH
XSSTRIKE_CMD = "xsstrike"       # Assumes xsstrike is in PATH
LFI_FINDER_SCRIPT = "lfi_finder.py" # Assume this script exists in the current dir or PATH

OUTPUT_DIR = "scan_results"
SQLMAP_OUTPUT_DIR = os.path.join(OUTPUT_DIR, "sqlmap_logs")
MAX_WORKERS = 10 # Number of concurrent scans
REQUEST_TIMEOUT = 10 # Timeout in seconds for individual tool checks where applicable

# URL extensions to target (lowercase)
TARGET_EXTENSIONS = {'.php', '.asp', '.html', '.htm', '.cfc', '.aspx', '.cgi', '.rb', '.py', '.pl', '.cfm', '.jsp', '.json', '.js'}

# --- Helper Functions ---

def print_status(msg):
    """Prints a status message."""
    print(f"[*] {datetime.now().strftime('%H:%M:%S')} {msg}")

def print_success(msg):
    """Prints a success message."""
    print(f"[+] {datetime.now().strftime('%H:%M:%S')} {msg}")

def print_error(msg):
    """Prints an error message."""
    print(f"[-] {datetime.now().strftime('%H:%M:%S')} {msg}", file=sys.stderr)

def run_command(cmd_list, timeout=None):
    """Executes a shell command and returns its stdout."""
    print_status(f"Executing: {' '.join(shlex.quote(arg) for arg in cmd_list)}")
    try:
        process = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            check=False, # Don't raise exception on non-zero exit code
            timeout=timeout
        )
        if process.returncode != 0:
            print_error(f"Command failed with code {process.returncode}: {' '.join(shlex.quote(arg) for arg in cmd_list)}")
            print_error(f"Stderr: {process.stderr.strip()}")
        # Always return stdout, even if command failed, it might contain partial info
        return process.stdout.strip()
    except subprocess.TimeoutExpired:
        print_error(f"Command timed out after {timeout}s: {' '.join(shlex.quote(arg) for arg in cmd_list)}")
        return None
    except FileNotFoundError:
        print_error(f"Command not found: {cmd_list[0]}. Is it installed and in PATH?")
        return None
    except Exception as e:
        print_error(f"Error executing command {' '.join(shlex.quote(arg) for arg in cmd_list)}: {e}")
        return None

def get_domain(url):
    """Extracts the domain name from a URL."""
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except Exception as e:
        print_error(f"Could not parse domain from URL '{url}': {e}")
        return None

def sanitize_filename(name):
    """Removes potentially problematic characters for filenames."""
    name = re.sub(r'[^\w\-.]', '_', name)
    return name

# --- Tool Execution Functions ---

def run_subfinder(target_domain):
    """Runs Subfinder to find subdomains."""
    print_status(f"Running Subfinder for {target_domain}...")
    if not os.path.exists(SUBFINDER_SCRIPT):
        print_error(f"Subfinder script not found at {SUBFINDER_SCRIPT}")
        return []
    # Assuming subfinder/main.py takes -d for domain and -silent
    cmd = [sys.executable, SUBFINDER_SCRIPT, "-d", target_domain, "-silent"]
    output = run_command(cmd)
    if output:
        subdomains = output.splitlines()
        print_success(f"Found {len(subdomains)} subdomains via Subfinder.")
        return [s.strip() for s in subdomains if s.strip()]
    return []

def run_waybackurls(domain):
    """Runs waybackurls to fetch URLs for a domain."""
    print_status(f"Running waybackurls for {domain}...")
    cmd = [WAYBACKURLS_CMD, domain]
    # Increase timeout for potentially long waybackurls calls
    output = run_command(cmd, timeout=300)
    if output:
        urls = output.splitlines()
        print_success(f"Found {len(urls)} potential URLs via waybackurls for {domain}.")
        return [u.strip() for u in urls if u.strip()]
    return []

def filter_urls(urls):
    """Filters URLs by extension and uniqueness, keeping parameters."""
    print_status(f"Filtering {len(urls)} URLs...")
    filtered = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path
            ext = os.path.splitext(path)[1].lower()
            if ext in TARGET_EXTENSIONS:
                 # Reconstruct URL to ensure consistency, handle potential parsing issues
                url_clean = urlunparse(parsed)
                filtered.add(url_clean)
        except ValueError:
            print_error(f"Skipping malformed URL: {url}")
            continue # Skip malformed URLs

    print_success(f"Got {len(filtered)} unique URLs matching extensions.")
    return list(filtered)

def check_sqlmap(url):
    """Runs SQLMap against a single URL."""
    print_status(f"SQLMap check: {url}")
    sanitized_url_part = sanitize_filename(urlparse(url).netloc + urlparse(url).path)
    log_file = os.path.join(SQLMAP_OUTPUT_DIR, f"sqlmap_log_{sanitized_url_part[:50]}.txt") # Limit filename length
    cmd = [
        SQLMAP_CMD, "-u", url,
        "--batch",              # Assume defaults, no interactive questions
        "--timeout", str(REQUEST_TIMEOUT),
        "--output-dir", SQLMAP_OUTPUT_DIR, # Specify output dir
        "--random-agent",       # Use random User-Agent
        "--level=3",            # Test level (1-5)
        "--risk=2",             # Risk level (1-3)
        #"--flush-session",      # Uncomment to clear session files for the target URL if needed
        # Attempt to log results, parsing can be complex, focus on vulnerability indication
        # SQLMap doesn't have a simple flag for just "is vulnerable". We check common output patterns.
    ]
    # SQLMap's timeout is per request, not total scan. Run with overall timeout.
    output = run_command(cmd, timeout=REQUEST_TIMEOUT * 10) # Give SQLMap more overall time

    if output:
        # Basic check for vulnerability indicators in stdout
        # This is NOT foolproof, proper sqlmap result parsing is complex
        vuln_indicators = [
            "appears to be injectable",
            "is vulnerable",
            "Parameter:",
            "GET parameter",
            "POST parameter",
        ]
        if any(indicator in output for indicator in vuln_indicators):
             print_success(f"SQLMap indicated potential vulnerability for: {url}")
             return url # Return URL if potentially vulnerable
    # Could also check files in SQLMAP_OUTPUT_DIR if needed, but adds complexity
    return None # Indicate not found or error

def check_xss(url):
    """Runs XSStrike against a single URL."""
    print_status(f"XSStrike check: {url}")
    # Note: XSStrike payload integration might differ. Assuming --seeds works.
    # If XSStrike doesn't take payload files, this needs modification.
    # Consider --crawl if needed, but can be slow.
    cmd = [
        XSSTRIKE_CMD, "-u", url,
        "--timeout", str(REQUEST_TIMEOUT),
        # "--seeds", XSS_PAYLOADS, # Assuming XSStrike uses --seeds for payload lists
        # If --seeds doesn't work, remove it. XSStrike has its own payloads.
        # XSStrike might be interactive or produce verbose output. Parsing needed.
    ]
    output = run_command(cmd, timeout=REQUEST_TIMEOUT * 5) # Give XSStrike decent time

    if output:
        # Basic check for vulnerability indicators in stdout
        # This is heuristic and depends heavily on XSStrike's output format.
        vuln_indicators = [
            "Payload:",
            "Reflected:",
            "DOM:",
            "Vulnerability found",
            "potential XSS",
        ]
        if any(indicator.lower() in output.lower() for indicator in vuln_indicators):
            print_success(f"XSStrike indicated potential vulnerability for: {url}")
            return url # Return URL if potentially vulnerable
    return None

def check_lfi(url):
    """Runs the LFI Finder script against a single URL."""
    print_status(f"LFI check: {url}")
    if not os.path.exists(LFI_FINDER_SCRIPT):
        print_error(f"LFI Finder script not found at {LFI_FINDER_SCRIPT}. Skipping LFI checks.")
        return None
    if not os.path.exists(LFI_PAYLOADS):
        print_error(f"LFI Payloads file not found at {LFI_PAYLOADS}. Skipping LFI checks.")
        return None

    # Assuming lfi_finder.py takes -u URL -p PAYLOAD_FILE [--timeout TIMEOUT]
    cmd = [
        sys.executable, LFI_FINDER_SCRIPT,
        "-u", url,
        "-p", LFI_PAYLOADS,
        #"--timeout", str(REQUEST_TIMEOUT) # Assuming the script supports a timeout arg
    ]
    # If the script doesn't handle timeout internally, rely on subprocess timeout
    output = run_command(cmd, timeout=REQUEST_TIMEOUT * 5) # Give script time

    if output:
        # Basic check for vulnerability indicators in stdout
        # Highly dependent on the assumed lfi_finder.py output format.
        vuln_indicators = [
            "LFI found",
            "Vulnerable:",
            "Potential LFI",
            "/etc/passwd", # Common indicator if successful
            "root:",       # Common indicator if successful
        ]
        if any(indicator.lower() in output.lower() for indicator in vuln_indicators):
             print_success(f"LFI Finder indicated potential vulnerability for: {url}")
             return url # Return URL if potentially vulnerable
    return None

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Automated Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=MAX_WORKERS, help=f"Number of concurrent threads (default: {MAX_WORKERS})")
    parser.add_argument("--skip-sqlmap", action="store_true", help="Skip SQLMap scans")
    parser.add_argument("--skip-xss", action="store_true", help="Skip XSStrike scans")
    parser.add_argument("--skip-lfi", action="store_true", help="Skip LFI Finder scans")

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        print_error("URL must start with http:// or https://")
        sys.exit(1)

    target_domain = get_domain(args.url)
    if not target_domain:
        sys.exit(1)

    print_status(f"Starting scan for {target_domain}...")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(SQLMAP_OUTPUT_DIR, exist_ok=True)

    # 1. Subdomain Discovery
    subdomains = run_subfinder(target_domain)
    all_domains = set([target_domain] + subdomains) # Include base domain
    print_status(f"Total unique domains/subdomains to scan: {len(all_domains)}")

    # 2. URL Discovery (Waybackurls)
    all_raw_urls = []
    # Using ThreadPoolExecutor for fetching waybackurls concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_domain = {executor.submit(run_waybackurls, domain): domain for domain in all_domains}
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                urls = future.result()
                if urls:
                    all_raw_urls.extend(urls)
            except Exception as exc:
                print_error(f"{domain} generated an exception during waybackurls: {exc}")

    print_status(f"Collected {len(all_raw_urls)} raw URLs from waybackurls.")

    # 3. Filter URLs
    target_urls = filter_urls(all_raw_urls)
    if not target_urls:
        print_error("No target URLs found after filtering. Exiting.")
        sys.exit(0)

    print_status(f"Prepared {len(target_urls)} unique URLs for scanning.")

    # 4. Run Scans Concurrently
    sqli_vuln = []
    xss_vuln = []
    lfi_vuln = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        if not args.skip_sqlmap:
            futures.update({executor.submit(check_sqlmap, url): ("sqli", url) for url in target_urls})
        if not args.skip_xss:
            futures.update({executor.submit(check_xss, url): ("xss", url) for url in target_urls})
        if not args.skip_lfi:
             # Check if LFI script exists before submitting tasks
            if os.path.exists(LFI_FINDER_SCRIPT) and os.path.exists(LFI_PAYLOADS):
                futures.update({executor.submit(check_lfi, url): ("lfi", url) for url in target_urls})
            else:
                 print_error("LFI script or payloads not found, skipping LFI scans.")


        total_tasks = len(futures)
        completed_tasks = 0
        print_status(f"Submitting {total_tasks} scan tasks...")

        for future in as_completed(futures):
            scan_type, url = futures[future]
            completed_tasks += 1
            print_status(f"Progress: {completed_tasks}/{total_tasks} tasks completed.")
            try:
                result = future.result()
                if result: # If the function returned a URL, it's considered vulnerable
                    if scan_type == "sqli":
                        sqli_vuln.append(result)
                    elif scan_type == "xss":
                        xss_vuln.append(result)
                    elif scan_type == "lfi":
                        lfi_vuln.append(result)
            except Exception as exc:
                print_error(f"URL {url} ({scan_type}) generated an exception during scan: {exc}")

    # 5. Save Results
    print_status("Saving results...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if sqli_vuln:
        sqli_file = os.path.join(OUTPUT_DIR, f"sqli_vuln_{timestamp}.txt")
        with open(sqli_file, 'w') as f:
            for url in sqli_vuln:
                f.write(url + '\n')
        print_success(f"SQLi vulnerabilities saved to {sqli_file}")
    else:
        print_status("No SQLi vulnerabilities found.")

    if xss_vuln:
        xss_file = os.path.join(OUTPUT_DIR, f"xss_vuln_{timestamp}.txt")
        with open(xss_file, 'w') as f:
            for url in xss_vuln:
                f.write(url + '\n')
        print_success(f"XSS vulnerabilities saved to {xss_file}")
    else:
        print_status("No XSS vulnerabilities found.")

    if lfi_vuln:
        lfi_file = os.path.join(OUTPUT_DIR, f"lfi_vuln_{timestamp}.txt")
        with open(lfi_file, 'w') as f:
            for url in lfi_vuln:
                f.write(url + '\n')
        print_success(f"LFI vulnerabilities saved to {lfi_file}")
    else:
        print_status("No LFI vulnerabilities found.")

    print_status("Scan finished.")


if __name__ == "__main__":
    main() 