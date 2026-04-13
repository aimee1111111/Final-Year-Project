from heuristics import heuristic_score, verdict, tips

def test_heuristic_score_for_phishing_text():
    text = "Urgent action required. Verify your account now or it will be suspended."
    result = heuristic_score(text)

    assert result["score"] > 0
    assert len(result["reasons"]) > 0

def test_heuristic_score_for_safe_text():
    text = "Hi, just checking if you are free for class tomorrow."
    result = heuristic_score(text)

    assert result["score"] >= 0
    assert isinstance(result["reasons"], list)

def test_tips_returns_list():
    result = tips()

    assert isinstance(result, list)
    assert len(result) > 0

def test_verdict_highly_suspicious():
    result = verdict(90, 0.9)

    assert result["label"] == "⚠️ Highly Suspicious"
    assert result["color"] == "red"

def test_verdict_low_risk():
    result = verdict(10, 0.1)

    assert result["label"] == "🟢 Low Risk"
    assert result["color"] == "green"