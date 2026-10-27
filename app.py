"""NetSentinel AI — local cybersecurity triage prototype.
Uses transparent heuristics, not a trained ML model or a live packet sniffer.
All response actions are advisory and require human approval.
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from datetime import datetime
from pathlib import Path
import csv, io, json, os
from detector import analyze_event, demo_events
from response_engine import recommend_response

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)
EVENTS_FILE = DATA_DIR / 'events.json'
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'netsentinel-demo-change-this-secret')


def load_events():
    if not EVENTS_FILE.exists(): return []
    try:
        data = json.loads(EVENTS_FILE.read_text(encoding='utf-8'))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError): return []


def save_events(events):
    EVENTS_FILE.write_text(json.dumps(events[:1000], indent=2), encoding='utf-8')


def enrich(raw):
    event = analyze_event(raw)
    event['response'] = recommend_response(event)
    event['status'] = raw.get('status', 'New')
    event['category'] = category_for(event['event_type'])
    return event


def category_for(event_type):
    text = event_type.lower()
    if 'brute' in text or 'login' in text or 'auth' in text: return 'Credential Access'
    if 'scan' in text: return 'Reconnaissance'
    if 'malware' in text: return 'Malware Indicator'
    if 'outbound' in text or 'transfer' in text: return 'Possible Data Transfer'
    if 'dns' in text: return 'DNS Activity'
    return 'Network Activity'


@app.route('/')
def dashboard():
    events = load_events()
    counts = {k: sum(1 for e in events if e.get('risk_level', '').lower() == k) for k in ('high','medium','low')}
    high_events = [e for e in events if e.get('risk_level') == 'High']
    source_counts = {}
    for e in events:
        if e.get('risk_level') in ('High', 'Medium'):
            source_counts[e.get('source_ip', 'unknown')] = source_counts.get(e.get('source_ip', 'unknown'), 0) + 1
    top_sources = sorted(source_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    return render_template('index.html', events=events[:100], counts=counts, total=len(events),
                           high_events=high_events[:5], top_sources=top_sources)


@app.route('/demo', methods=['POST'])
def load_demo():
    events = load_events(); ids = {e.get('id') for e in events}
    for raw in demo_events():
        if raw['id'] not in ids: events.insert(0, enrich(raw))
    save_events(events)
    flash('Simulated sample events loaded. These are not live traffic.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/analyze', methods=['POST'])
def analyze_custom():
    raw = {'id': f"manual-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
           'timestamp': datetime.now().isoformat(timespec='seconds'),
           'source_ip': request.form.get('source_ip', '').strip() or 'unknown',
           'event_type': request.form.get('event_type', 'other').strip(),
           'failed_attempts': request.form.get('failed_attempts', '0'),
           'destination_port': request.form.get('destination_port', '0'),
           'bytes_sent': request.form.get('bytes_sent', '0'), 'notes': request.form.get('notes', '').strip()}
    try:
        raw['failed_attempts'] = max(0, int(raw['failed_attempts']))
        raw['destination_port'] = int(raw['destination_port'])
        raw['bytes_sent'] = max(0, int(raw['bytes_sent']))
        if not 0 <= raw['destination_port'] <= 65535: raise ValueError
    except ValueError:
        flash('Check numeric fields: whole numbers only, destination port 0–65535.', 'error')
        return redirect(url_for('dashboard'))
    events = load_events(); events.insert(0, enrich(raw)); save_events(events)
    flash('Event analyzed, risk-scored, explained, and saved locally.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/api/assistant', methods=['POST'])
def assistant():
    payload = request.get_json(silent=True) or {}
    question = str(payload.get('message', '')).strip().lower()[:500]
    events = load_events()
    highs = [e for e in events if e.get('risk_level') == 'High']
    mediums = [e for e in events if e.get('risk_level') == 'Medium']
    latest = events[0] if events else None
    if not question:
        answer = 'Ask me about high-risk alerts, recent events, risk scores, or safe response steps.'
    elif any(word in question for word in ('high risk','high-risk','critical','latest alert','latest high')):
        if highs:
            e = highs[0]
            answer = (f"Latest high-risk event: {e.get('event_type')} from {e.get('source_ip')} (score {e.get('risk_score')}/100). "
                      f"Reason: {e.get('explanation')} Recommended next step: validate the evidence in trusted logs, then follow your incident runbook. No automatic blocking is performed.")
        else: answer = 'There are no high-risk events in the local history. Load sample events or analyze an event to try the workflow.'
    elif any(word in question for word in ('summary','overview','how many','status','events')):
        answer = f"Local history contains {len(events)} events: {len(highs)} high risk, {len(mediums)} medium risk, and {len(events)-len(highs)-len(mediums)} low risk. " + (f"Latest event: {latest.get('event_type')} ({latest.get('risk_level')}, {latest.get('risk_score')}/100)." if latest else 'No events have been recorded yet.')
    elif any(word in question for word in ('respond','response','what should','action','block')):
        if latest:
            steps = latest.get('response') or ['Review the event context and logs.']
            answer = 'Safe response checklist for the latest event: ' + ' '.join(f'{i+1}. {step}' for i, step in enumerate(steps)) + ' This assistant never executes response actions.'
        else: answer = 'First load sample events or analyze an event. Then I can provide a contextual response checklist.'
    elif any(word in question for word in ('score','risk','why')):
        if latest: answer = f"Latest risk score is {latest.get('risk_score')}/100 ({latest.get('risk_level')}). Factors: {latest.get('explanation')} Scores are transparent demo heuristics, not a trained AI model or a universal security rating."
        else: answer = 'No event to score yet. Analyze an event to see which configured factors affect its score.'
    else:
        answer = 'I can summarize event counts, explain the latest risk score, highlight high-risk alerts, and suggest safe investigation steps. This is a local rule-based assistant; connect a vetted model later if you need genuine LLM conversation.'
    return jsonify({'answer': answer, 'mode': 'local-rule-assistant'})


@app.route('/export.csv')
def export_csv():
    events = load_events(); output = io.StringIO(); fields = ['timestamp','source_ip','event_type','category','risk_score','risk_level','status','failed_attempts','destination_port','bytes_sent','explanation','notes']
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore'); writer.writeheader(); writer.writerows(events)
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=netsentinel-events.csv'})


@app.route('/report.txt')
def report():
    events = load_events(); now = datetime.now().isoformat(timespec='seconds')
    lines = ['NETSENTINEL AI — LOCAL SECURITY TRIAGE REPORT', f'Generated: {now}', 'Scope: locally entered or simulated events only', '='*58,
             f'Total events: {len(events)}', f"High risk: {sum(e.get('risk_level')=='High' for e in events)}",
             f"Medium risk: {sum(e.get('risk_level')=='Medium' for e in events)}", f"Low risk: {sum(e.get('risk_level')=='Low' for e in events)}", '', 'EVENT DETAILS']
    for e in events:
        lines += ['', f"[{e.get('risk_level')} {e.get('risk_score')}/100] {e.get('timestamp')} — {e.get('event_type')}",
                  f"Source: {e.get('source_ip')} | Category: {e.get('category','Network Activity')} | Status: {e.get('status','New')}",
                  f"Explanation: {e.get('explanation')}", 'Suggested response:'] + [f" - {s}" for s in e.get('response', [])]
    lines += ['', 'LIMITATIONS: heuristic scoring only; no trained ML model, live packet capture, or automated blocking. Validate alerts before acting.', '']
    return Response('\n'.join(lines), mimetype='text/plain; charset=utf-8', headers={'Content-Disposition':'attachment; filename=netsentinel-incident-report.txt'})


@app.route('/clear', methods=['POST'])
def clear_events():
    save_events([]); flash('Local event history cleared.', 'success'); return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)
