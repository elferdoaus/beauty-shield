def calculate_risk(issues):
    score = 0

    for issue in issues:
        if issue["severity"] == "HIGH":
            score += 40
        elif issue["severity"] == "MEDIUM":
            score += 20
        elif issue["severity"] == "LOW":
            score += 10

    if score > 100:
        score = 100

    if score >= 70:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level