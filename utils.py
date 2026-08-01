"""
utils.py
Utility functions for VTBulkScanner

Author: Abhinav Maurya
"""

from urllib.parse import urlparse
from datetime import datetime


def is_valid_url(url: str) -> bool:
    """
    Validate URL format.
    Automatically adds https:// if scheme is missing.
    """

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    return bool(parsed.scheme and parsed.netloc)


def normalize_url(url: str) -> str:
    """
    Ensure URL has a scheme.
    """

    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def read_urls(file_path: str):
    """
    Read URLs from a text file.
    Removes duplicates and invalid URLs.
    """

    urls = []
    seen = set()

    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:

            url = normalize_url(line)

            if not url:
                continue

            if not is_valid_url(url):
                print(f"[!] Invalid URL skipped: {url}")
                continue

            if url not in seen:
                urls.append(url)
                seen.add(url)

    return urls


def format_timestamp(timestamp):
    """
    Convert Unix timestamp to readable format.
    """

    if not timestamp:
        return "N/A"

    try:
        return datetime.fromtimestamp(
            timestamp
        ).strftime("%Y-%m-%d %H:%M:%S")

    except Exception:
        return "N/A"


def print_summary(results):
    """
    Print scan summary.
    """

    total = len(results)

    malicious = sum(
        1 for r in results
        if r.get("malicious", 0) > 0
    )

    clean = total - malicious

    failed = sum(
        1 for r in results
        if r.get("status") != "Success"
    )

    print("\n" + "=" * 50)
    print("Scan Summary")
    print("=" * 50)
    print(f"Total URLs      : {total}")
    print(f"Clean URLs      : {clean}")
    print(f"Malicious URLs  : {malicious}")
    print(f"Failed Scans    : {failed}")
    print("=" * 50)
