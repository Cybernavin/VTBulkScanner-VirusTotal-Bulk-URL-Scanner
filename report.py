"""
report.py
Generate CSV, JSON, and HTML reports.

Author: Abhinav Maurya
"""

import csv
import json
import os
from datetime import datetime

OUTPUT_DIR = "output"

CSV_FILE = os.path.join(OUTPUT_DIR, "results.csv")
JSON_FILE = os.path.join(OUTPUT_DIR, "results.json")
HTML_FILE = os.path.join(OUTPUT_DIR, "results.html")


def timestamp_to_date(timestamp):
    """
    Convert Unix timestamp to readable date.
    """
    try:
        if timestamp:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return "N/A"


def generate_csv(results):
    """
    Generate CSV report.
    """

    fields = [
        "url",
        "status",
        "harmless",
        "malicious",
        "suspicious",
        "undetected",
        "timeout",
        "failure",
        "reputation",
        "last_analysis_date",
        "message"
    ]

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)

        writer.writeheader()

        for row in results:
            row = row.copy()

            if "last_analysis_date" in row:
                row["last_analysis_date"] = timestamp_to_date(
                    row["last_analysis_date"]
                )

            writer.writerow(row)


def generate_json(results):
    """
    Generate JSON report.
    """

    data = []

    for row in results:
        item = row.copy()

        if "last_analysis_date" in item:
            item["last_analysis_date"] = timestamp_to_date(
                item["last_analysis_date"]
            )

        data.append(item)

    with open(JSON_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def generate_html(results):
    """
    Generate HTML report.
    """

    rows = ""

    for result in results:

        malicious = result.get("malicious", 0)

        if malicious > 0:
            color = "#ff4d4d"
            verdict = "Malicious"
        else:
            color = "#4CAF50"
            verdict = "Clean"

        rows += f"""
        <tr>
            <td>{result.get("url","")}</td>
            <td>{result.get("status","")}</td>
            <td>{result.get("harmless","")}</td>
            <td>{result.get("malicious","")}</td>
            <td>{result.get("suspicious","")}</td>
            <td>{result.get("undetected","")}</td>
            <td>{result.get("reputation","")}</td>
            <td>{timestamp_to_date(result.get("last_analysis_date"))}</td>
            <td style="color:{color};font-weight:bold;">{verdict}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VTBulkScanner Report</title>

<style>

body{{
font-family:Arial,Helvetica,sans-serif;
background:#f4f4f4;
margin:40px;
}}

h1{{
text-align:center;
}}

table{{
width:100%;
border-collapse:collapse;
background:white;
}}

th{{
background:#222;
color:white;
padding:12px;
}}

td{{
padding:10px;
border:1px solid #ddd;
text-align:center;
}}

tr:nth-child(even){{
background:#f2f2f2;
}}

</style>

</head>

<body>

<h1>VirusTotal Bulk URL Scanner Report</h1>

<table>

<tr>
<th>URL</th>
<th>Status</th>
<th>Harmless</th>
<th>Malicious</th>
<th>Suspicious</th>
<th>Undetected</th>
<th>Reputation</th>
<th>Analysis Date</th>
<th>Verdict</th>
</tr>

{rows}

</table>

</body>
</html>
"""

    with open(HTML_FILE, "w", encoding="utf-8") as file:
        file.write(html)
