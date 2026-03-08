def calculate_threat_score(severity):
    """
    Base threat score from severity level.
    Callers can multiply by a confidence factor if needed.
    """
    scores = {
        "CRITICAL": 15,
        "HIGH":     10,
        "MEDIUM":    5,
        "LOW":       1,
        "INFO":      0,
    }
    return scores.get(severity.upper(), 1)
