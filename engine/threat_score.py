def calculate_threat_score(severity):
    scores = {
        "LOW": 1,
        "MEDIUM": 5,
        "HIGH": 10
    }
    return scores.get(severity.upper(), 1)
