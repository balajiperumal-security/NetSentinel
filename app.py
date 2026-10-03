from flask import Flask, render_template_string
import re
from collections import Counter

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head><meta http-equiv="refresh" content="5">
<title>NetSentinel Dashboard</title>

<style>
body {
    font-family: Arial;
    background: #111827;
    color: white;
    margin: 30px;
}

.card {
    display: inline-block;
    background: #1f2937;
    padding: 20px;
    margin: 10px;
    border-radius: 10px;
}

.alert {
    background: #374151;
    padding: 20px;
    margin-top: 25px;
    border-radius: 10px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}

th, td {
    padding: 10px;
    border-bottom: 1px solid #374151;
    text-align: left;
}
</style>
</head>

<body>

<h1>🛡️ NetSentinel</h1>

<p>Lightweight Network Behavior & Threat Detection System</p>

<div class="card">
<h3>Total Events</h3>
<h2>{{ total }}</h2>
</div>

<div class="card">
<h3>High Risk</h3>
<h2>{{ high }}</h2>
</div>

<div class="card">
<h3>Medium Risk</h3>
<h2>{{ medium }}</h2>
</div>

<div class="card">
<h3>Low Risk</h3>
<h2>{{ low }}</h2>
</div>

<div class="alert">

<h2>🔎 Security Analysis</h2>

<p><b>Current Status:</b> {{ status }}</p>

<p><b>Explanation:</b> {{ explanation }}</p>

<p><b>Recommended Action:</b> {{ action }}</p>

<p><b>Verification:</b> Continue monitoring subsequent traffic.</p>

</div>

<h2>Recent Traffic</h2>

<table>

<tr>
<th>Time</th>
<th>Source</th>
<th>Destination</th>
<th>Protocol</th>
<th>Port</th>
<th>Risk</th>
</tr>

{% for row in rows %}

<tr>
{% for item in row %}
<td>{{ item }}</td>
{% endfor %}
</tr>

{% endfor %}

</table>

</body>
</html>
"""


@app.route("/")
def dashboard():

    rows = []
    risk_counts = Counter()

    try:
        with open("traffic_log.txt", "r") as file:
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

                risk_counts[risk] += 1

                rows.append([
                    time,
                    src,
                    dst,
                    protocol,
                    port,
                    risk
                ])

    except FileNotFoundError:
        pass

    total = len(rows)

    high = risk_counts["HIGH"]
    medium = risk_counts["MEDIUM"]
    low = total - high - medium

    if high > 0:
        status = "HIGH RISK"
        explanation = "Potentially sensitive or risky network ports were observed."
        action = "Review the source and destination and investigate the activity."

    elif medium > 0:
        status = "MEDIUM RISK"
        explanation = "Repeated network activity requires additional monitoring."
        action = "Continue monitoring and investigate unusual activity."

    else:
        status = "LOW RISK"
        explanation = "Observed traffic is currently within the configured monitoring threshold."
        action = "Continue normal monitoring."

    return render_template_string(
        HTML,
        total=total,
        high=high,
        medium=medium,
        low=low,
        status=status,
        explanation=explanation,
        action=action,
        rows=rows[-20:]
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000
    )
