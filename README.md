# NetSentinel AI — v2.0 Student Prototype

A local Flask cybersecurity triage dashboard with a green Sentinel Bot mascot, explainable heuristic risk scoring, a local rule-based assistant, searchable event history, CSV export, and text incident reports.

## Included features
- Dark SOC-style dashboard with green robot assistant
- Event analyzer for brute-force indicators, port-scan indicators, malware indicators, unusual outbound transfers, suspicious DNS, and normal/other events
- Transparent score (0–100) with Low / Medium / High bands and factor explanations
- Suggested response checklist that requires human review
- Local JSON history in `data/events.json`
- Simulated demo events (clearly labelled as simulated)
- Search and filter recent events by risk level
- Local assistant for event summaries, high-risk explanations, risk scores, and safe response guidance
- Downloadable CSV event evidence and plain-text incident report
- Unit tests for scoring logic

## Setup on Linux Mint
Open Terminal and enter one step at a time:

```bash
cd ~/Downloads
unzip NetSentinel_AI.zip
cd NetSentinel_AI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser. Keep the terminal open while using the dashboard. To stop the local server, press `Ctrl+C` in the terminal.

If your ZIP is saved somewhere other than Downloads, move to that folder first. `python3-venv` may need to be installed through your Linux distribution's package manager if creating the virtual environment fails.

## Run tests
Activate the virtual environment, then run:

```bash
python -m unittest discover -s tests -v
```

## Important accuracy and safety notes
- The current assistant is **local rule-based**, not a trained machine-learning model or a connected LLM. The robot is the UI mascot.
- Event detection and risk scoring use transparent demo heuristics; tune thresholds against a labelled dataset before claiming real-world detection performance.
- This package does not sniff live network traffic, execute shell commands, block IP addresses, or automatically change system settings.
- Sample addresses and event records are simulated documentation examples, not evidence of real attacks.
- Use only on systems and networks you own or have explicit permission to assess. Review alerts and obtain human approval before any incident-response action.
- The Flask development server binds to `127.0.0.1` for local use. Do not expose it publicly without proper authentication, deployment hardening, and security review.

## Project architecture
- `app.py` — routes, local history, assistant, exports, report generation
- `detector.py` — transparent event scoring and demo records
- `risk_engine.py` — risk band helper
- `response_engine.py` — advisory response playbooks
- `templates/index.html` — dashboard layout
- `static/style.css` — responsive dark SOC UI
- `static/app.js` — search/filter and assistant chat interactions
- `static/green_sentinel_bot.png` — original dashboard mascot crop
- `tests/` — unit tests


## Deploy to Render
This repository includes `render.yaml` and Gunicorn for Render deployment. Import this folder/repository into GitHub, then in Render choose **New + → Blueprint** and select the repository containing `render.yaml`. If updating an existing Render service, ensure its root directory is `NetSentinel_AI` if the folder remains nested, and set the start command to `gunicorn app:app --workers 1 --threads 4 --timeout 120`.

**Important:** This is a demonstration prototype, not production-ready security software. Public deployment has no user authentication and uses local JSON storage, which may be reset on redeploy. Do not enter sensitive or real incident data. Review and secure routes before public/real-world use.


## Added interactive companion features
- Animated floating/pulsing Sentinel robot artwork with a thinking animation while the assistant is processing.
- Browser speech synthesis for spoken assistant replies (turn on/off in the dashboard).
- Optional browser speech recognition input when supported and microphone permission is granted; typing always remains available.
- Live browser clock and status feedback.

Voice features run in the user's browser and depend on browser support/permissions. The assistant remains a local rule-based helper; these additions do not create a trained AI model or real-time network monitoring.

## Deployment note
This is a student demo, not a production SOC. Do not enter secrets or real sensitive incident data. The public demo has no user authentication, and event history may be ephemeral on hosted platforms. Before using it with real users, add authentication, authorization/CSRF protection, durable storage controls, and security review.
