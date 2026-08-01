"""
scanner.py
VirusTotal URL Scanner

Author: Abhinav Maurya
"""

import base64
import requests

from config import API_KEY

VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls"


def url_to_id(url: str) -> str:
    """
    Convert a URL into VirusTotal's URL ID format.
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded


def scan_url(url: str) -> dict:
    """
    Scan a single URL using the VirusTotal API.

    Returns:
        dict
    """

    headers = {
        "x-apikey": API_KEY
    }

    try:
        # Submit URL for analysis
        response = requests.post(
            VT_URL_REPORT,
            headers=headers,
            data={"url": url},
            timeout=30
        )

        if response.status_code != 200:
            return {
                "url": url,
                "status": "Failed",
                "message": f"HTTP {response.status_code}: {response.text}"
            }

        # Generate URL ID
        url_id = url_to_id(url)

        # Fetch analysis result
        report_url = f"{VT_URL_REPORT}/{url_id}"

        report = requests.get(
            report_url,
            headers=headers,
            timeout=30
        )

        if report.status_code != 200:
            return {
                "url": url,
                "status": "Failed",
                "message": f"HTTP {report.status_code}: {report.text}"
            }

        data = report.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "url": url,
            "status": "Success",
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "failure": stats.get("failure", 0),
            "reputation": data["data"]["attributes"].get("reputation", 0),
            "last_analysis_date": data["data"]["attributes"].get(
                "last_analysis_date", ""
            ),
            "message": "Success"
        }

    except requests.exceptions.Timeout:
        return {
            "url": url,
            "status": "Failed",
            "message": "Request timed out"
        }

    except requests.exceptions.ConnectionError:
        return {
            "url": url,
            "status": "Failed",
            "message": "Connection error"
        }

    except Exception as e:
        return {
            "url": url,
            "status": "Failed",
            "message": str(e)
        }
