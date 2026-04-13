import os
from storage import append_labeled_example, load_labeled_examples, save_state, load_state

def test_append_and_load_examples(tmp_path, monkeypatch):
    test_data_file = tmp_path / "test_examples.jsonl"
    monkeypatch.setattr("storage.DATA_FILE", str(test_data_file))

    append_labeled_example("phishing text", 1)
    append_labeled_example("safe text", 0)

    X, y = load_labeled_examples()

    assert len(X) == 2
    assert X[0] == "phishing text"
    assert y == [1, 0]


def test_save_and_load_state(tmp_path, monkeypatch):
    test_state_file = tmp_path / "test_state.json"
    monkeypatch.setattr("storage.STATE_FILE", str(test_state_file))

    state = {
        "feedback_count": 3,
        "online_since_rebuild": 1,
        "last_retrain_ts": 12345
    }

    save_state(state)
    loaded = load_state()

    assert loaded["feedback_count"] == 3
    assert loaded["online_since_rebuild"] == 1
    assert loaded["last_retrain_ts"] == 12345