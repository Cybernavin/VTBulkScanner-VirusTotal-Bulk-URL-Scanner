"""
VTBulkScanner
Main Entry Point

Author: Abhinav Maurya
"""

import argparse
import os
import time
from colorama import Fore, init

from scanner import scan_url
from report import generate_csv, generate_json, generate_html
from utils import read_urls, print_summary

init(autoreset=True)


def banner():
    print(Fore.CYAN + "=" * 65)
    print("           VTBulkScanner - VirusTotal Bulk URL Scanner")
    print("=" * 65)
    print()


def main():

    parser = argparse.ArgumentParser(
        prog="VTBulkScanner",
        description="Bulk URL Scanner using VirusTotal API"
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to the input text file containing URLs."
    )

    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output directory (default: output)"
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=int,
        default=16,
        help="Delay between VirusTotal API requests in seconds (default: 16)"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="VTBulkScanner v1.0"
    )

    args = parser.parse_args()

    banner()

    if not os.path.isfile(args.input):
        print(Fore.RED + f"[!] Input file not found:\n{args.input}")
        return

    os.makedirs(args.output, exist_ok=True)

    urls = read_urls(args.input)

    if not urls:
        print(Fore.RED + "[!] No valid URLs found in input file.")
        return

    print(Fore.YELLOW + f"[*] Loaded {len(urls)} URL(s)\n")

    results = []

    for index, url in enumerate(urls, start=1):

        print(Fore.BLUE + f"[{index}/{len(urls)}] Scanning: {url}")

        result = scan_url(url)

        results.append(result)

        if args.verbose:

            if result["status"] == "Success":

                print(
                    Fore.GREEN
                    + f"Harmless : {result.get('harmless',0)}"
                )

                print(
                    Fore.RED
                    + f"Malicious: {result.get('malicious',0)}"
                )

                print(
                    Fore.YELLOW
                    + f"Suspicious: {result.get('suspicious',0)}"
                )

            else:

                print(
                    Fore.RED
                    + f"Error: {result.get('message')}"
                )

        time.sleep(args.delay)

    print("\n" + Fore.YELLOW + "Generating reports...")

    generate_csv(results, args.output)
    generate_json(results, args.output)
    generate_html(results, args.output)

    print_summary(results)

    print(Fore.GREEN + "\nReports generated successfully.")

    print(Fore.CYAN + f"CSV  : {args.output}/results.csv")
    print(Fore.CYAN + f"JSON : {args.output}/results.json")
    print(Fore.CYAN + f"HTML : {args.output}/results.html")

    print(Fore.GREEN + "\nDone.")


if __name__ == "__main__":
    main()
