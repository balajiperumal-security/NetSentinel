from datetime import datetime
import re
from collections import Counter

LOG_FILE = "traffic_log.txt"
REPORT_FILE = "netsentinel_report.txt"

rows = []

try:
    with open(LOG_FILE, "r") as file:
        lines = file.readlines()

    for line in lines:
        match = re.search(
            r"\[(.*?)\]\s+(\S+)\s+->\s+(\S+)\s+\|\s+(\S+)\s+\|\s+Port:\s+(\S+)",
            line
        )

        if match:
            time, src, dst, protocol, port = match.groups()

            if port in ["21", "23", "445", "3389"]:
                risk = "HIGH"
            else:
                risk = "LOW"

            rows.append([
                time, src, dst, protocol, port, risk
            ])

except FileNotFoundError:
    print("traffic_log.txt not found.")
    exit()


risk_counts = Counter(row[5] for row in rows)

with open(REPORT_FILE, "w") as report:

    report.write("=" * 60 + "\n")
    report.write("             NETSENTINEL SECURITY REPORT\n")
    report.write("=" * 60 + "\n\n")

    report.write(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    )

    report.write("SUMMARY\n")
    report.write("-" * 40 + "\n")
    report.write(f"Total Events : {len(rows)}\n")
    report.write(f"High Risk    : {risk_counts['HIGH']}\n")
    report.write(f"Medium Risk  : {risk_counts['MEDIUM']}\n")
    report.write(f"Low Risk     : {risk_counts['LOW']}\n\n")

    report.write("SECURITY ANALYSIS\n")
    report.write("-" * 40 + "\n")

    if risk_counts["HIGH"] > 0:
        report.write(
            "Potentially risky network ports were observed.\n"
        )
        report.write(
            "Recommended Action: Review the related traffic.\n"
        )
    else:
        report.write(
            "Observed traffic is currently within the configured "
            "monitoring threshold.\n"
        )
        report.write(
            "Recommended Action: Continue normal monitoring.\n"
        )

    report.write("\nTRAFFIC DETAILS\n")
    report.write("-" * 60 + "\n")

    for row in rows:
        report.write(
            f"{row[0]} | {row[1]} -> {row[2]} | "
            f"{row[3]} | Port: {row[4]} | Risk: {row[5]}\n"
        )

print("Report generated successfully!")
print(f"File: {REPORT_FILE}")
