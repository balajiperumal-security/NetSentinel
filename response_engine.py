"""Safe, advisory-only response recommendations. No automatic blocking/actions."""
def recommend_response(event):
    level = event.get('risk_level', 'Low')
    if level == 'High':
        return [
            'Validate the alert against trusted logs and asset context.',
            'If this is an authorized environment, notify the security owner and follow the incident runbook.',
            'Consider isolating the affected test host only after approval and impact review.',
            'Preserve relevant logs and record the investigation timeline.'
        ]
    if level == 'Medium':
        return [
            'Review related authentication and network logs.',
            'Confirm whether the activity matches an approved test or expected application behavior.',
            'Escalate if the indicator repeats or affects a sensitive asset.'
        ]
    return [
        'Continue routine monitoring.',
        'Keep the event available for correlation if similar activity appears later.'
    ]
