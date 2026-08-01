"""
VTBulkScanner
Main Entry Point

Author: Abhinav Maurya
"""

import os
import time
from colorama import Fore, Style, init

from scanner import scan_url
from report import generate_csv, generate_json, generate_html
from utils import read_urls

init(autoreset=True)

INPUT_FILE = "input/urls.txt"
OUTPUT_DIR = "output"


def banner():
    print(Fore.CYAN + "=" * 60)
    print("        VTBulkScanner - VirusTotal Bulk URL Scanner")
    print("=" * 60)
    print()


def check_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not os.path.exists(INPUT_FILE):
        print(Fore.RED + f"[!] Input file not found: {INPUT_FILE}")
        exit()


def main():

    banner()

    check_directories()

    urls = read_urls(INPUT_FILE)

    if not urls:
        print(Fore.RED + "[!] No URLs found.")
        return

    print(Fore.YELLOW + f"[*] Total URLs Loaded : {len(urls)}\n")

    results = []

    for index, url in enumerate(urls, start=1):

        print(Fore.BLUE + f"[{index}/{len(urls)}] Scanning -> {url}")

        result = scan_url(url)

        results.append(result)

        if result["status"] == "Success":
            print(
                Fore.GREEN
                + f"    Clean: {result['harmless']} | Malicious: {result['malicious']}"
            )
        else:
            print(Fore.RED + f"    Error: {result['message']}")

        print()

        # VirusTotal API rate limit safety
        time.sleep(16)

    print(Fore.YELLOW + "Generating reports...\n")

    generate_csv(results)
    generate_json(results)
    generate_html(results)

    print(Fore.GREEN + "Reports saved successfully.")
    print(Fore.GREEN + "Location: output/")
    print(Fore.CYAN + "\nDone.")


if __name__ == "__main__":
    main()
