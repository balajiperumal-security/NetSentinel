from collections import Counter
import re

LOG_FILE = "traffic_log.txt"

print("\n" + "=" * 55)
print("          NETSENTINEL RISK ENGINE")
print("=" * 55)

try:
    with open(LOG_FILE, "r") as file:
        data = file.read()

    ports = re.findall(r"Port:\s*(\d+)", data)
    counts = Counter(ports)

    print("\nTraffic Analysis:")

    if not counts:
        print("No traffic data found.")
    else:
        for port, count in counts.most_common():
            if count >= 20:
                risk = "HIGH"
            elif count >= 10:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            print(f"Port {port:5} | Events: {count:3} | Risk: {risk}")

except FileNotFoundError:
    print("traffic_log.txt not found.")
