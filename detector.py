"""Transparent heuristic event scoring for the NetSentinel AI demo.
This is not a trained machine-learning model and does not capture live traffic.
"""
from datetime import datetime

SUSPICIOUS_TYPES = {'port_scan', 'brute_force', 'malware_indicator', 'unusual_outbound'}

def analyze_event(raw):
    try:
        failed = int(raw.get('failed_attempts', 0))
        port = int(raw.get('destination_port', 0))
        byte_count = int(raw.get('bytes_sent', 0))
    except (TypeError, ValueError):
        failed, port, byte_count = 0, 0, 0
    event_type = str(raw.get('event_type', 'unknown')).lower().strip()
    score = 5
    reasons = []
    if event_type in SUSPICIOUS_TYPES:
        score += 35
        reasons.append(f"Event type '{event_type}' is marked suspicious by the demo rules")
    if failed >= 10:
        score += 35
        reasons.append(f'{failed} failed attempts reached the high threshold (10)')
    elif failed >= 5:
        score += 20
        reasons.append(f'{failed} failed attempts crossed the review threshold (5)')
    if port in {21, 22, 23, 445, 3389, 4444}:
        score += 15
        reasons.append(f'Destination port {port} is on the demo review list')
    if byte_count >= 5_000_000:
        score += 20
        reasons.append('Outbound byte count is at least 5 MB; review the context')
    score = min(score, 100)
    level = 'High' if score >= 70 else 'Medium' if score >= 35 else 'Low'
    if not reasons:
        reasons.append('No configured high-risk indicators matched; continue normal monitoring')
    event = {
        'id': str(raw.get('id', f"event-{datetime.now().timestamp()}")),
        'timestamp': str(raw.get('timestamp', datetime.now().isoformat(timespec='seconds'))),
        'source_ip': str(raw.get('source_ip', 'unknown')),
        'event_type': event_type.replace('_', ' ').title(),
        'failed_attempts': failed,
        'destination_port': port,
        'bytes_sent': byte_count,
        'notes': str(raw.get('notes', '')),
        'risk_score': score,
        'risk_level': level,
        'explanation': ' '.join(reasons),
    }
    return event

def demo_events():
    return [
        {'id':'demo-bruteforce-001','timestamp':datetime.now().isoformat(timespec='seconds'),'source_ip':'192.0.2.15','event_type':'brute_force','failed_attempts':14,'destination_port':22,'bytes_sent':1200,'notes':'Simulated repeated login failures'},
        {'id':'demo-outbound-002','timestamp':datetime.now().isoformat(timespec='seconds'),'source_ip':'192.0.2.44','event_type':'unusual_outbound','failed_attempts':0,'destination_port':443,'bytes_sent':8200000,'notes':'Simulated large outbound transfer'},
        {'id':'demo-normal-003','timestamp':datetime.now().isoformat(timespec='seconds'),'source_ip':'192.0.2.80','event_type':'normal_connection','failed_attempts':1,'destination_port':443,'bytes_sent':42000,'notes':'Simulated routine HTTPS activity'},
        {'id':'demo-portscan-004','timestamp':datetime.now().isoformat(timespec='seconds'),'source_ip':'192.0.2.99','event_type':'port_scan','failed_attempts':6,'destination_port':445,'bytes_sent':9000,'notes':'Simulated port scan indicator'},
    ]
