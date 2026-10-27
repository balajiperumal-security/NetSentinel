"""Small reusable risk helper; score bands are demo thresholds, not universal standards."""
def risk_level(score):
    score = max(0, min(100, int(score)))
    if score >= 70:
        return 'High'
    if score >= 35:
        return 'Medium'
    return 'Low'
