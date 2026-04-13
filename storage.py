"""
Storage functions for the phishing detector.

This file is responsible for saving and loading the local data used by the
phishing detection system. It manages the labelled training examples stored
in the JSONL file, reads and writes application state such as feedback and
retraining counters, and provides a helper function for checking when the
training data was last updated.
"""

import os
import json
import time
import sys
from typing import List, Dict, Tuple, Any, Optional
from config import DATA_FILE, STATE_FILE


# Creates the labelled data file if it does not already exist
def _ensure_datafile():
    if not os.path.exists(DATA_FILE):
        open(DATA_FILE, "a", encoding="utf-8").close()


# Appends one new labelled example to the JSONL training data file
def append_labeled_example(text: str, label: int, source: str = "user"):
    _ensure_datafile()

    rec = {
        "text": text,
        "label": int(1 if label else 0),
        "ts": time.time(),
        "source": source
    }

    with open(DATA_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# Loads all saved labelled examples and separates them into texts and labels
def load_labeled_examples() -> Tuple[List[str], List[int]]:
    if not os.path.exists(DATA_FILE):
        return [], []

    X, y = [], []

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                txt = (obj.get("text") or "").strip()

                if txt:
                    X.append(txt)
                    y.append(int(1 if obj.get("label") else 0))

            except Exception:
                continue

    return X, y


# Loads the saved application state, including feedback and retraining counters
def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_FILE):
        return {
            "feedback_count": 0,
            "online_since_rebuild": 0,
            "last_retrain_ts": None
        }

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    except Exception:
        return {
            "feedback_count": 0,
            "online_since_rebuild": 0,
            "last_retrain_ts": None
        }


# Saves the current application state back to disk
def save_state(state: Dict[str, Any]):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"State save error: {e}", file=sys.stderr)


# Returns the last modified timestamp of the labelled data file
def latest_data_timestamp() -> Optional[float]:
    if not os.path.exists(DATA_FILE):
        return None

    try:
        return os.path.getmtime(DATA_FILE)

    except Exception:
        return None