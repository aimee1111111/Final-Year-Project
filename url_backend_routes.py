"""
This file defines the backend routes used for phishing-related URL checks.

It creates a Flask Blueprint with two API endpoints:
1. /api/phishstats   -> checks whether a URL or domain appears in recent phishing records
2. /api/checkphish   -> submits a URL to the CheckPhish service and polls for the result

The file also handles common errors such as missing input, missing API keys,
timeouts, and failed external requests, then returns structured JSON results
that the frontend can display.
"""

from flask import Blueprint, request, jsonify
import os
import traceback
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv
import time

# Loads environment variables from the .env file
load_dotenv()

# Gets the CheckPhish API key from environment variables
CHECKPHISH_API_KEY = os.environ.get("CHECKPHISH_API_KEY")

# Creates a Flask Blueprint for phishing-related routes
phishing_bp = Blueprint("phishing", __name__)


@phishing_bp.route("/api/phishstats", methods=["GET"])
def api_phishstats():
    """
    Checks whether the given URL appears in recent phishing records from PhishStats.

    Query parameter:
    - url: the URL to check

    Returns:
    - a structured JSON result showing whether the domain appears in the feed
    """
    # Gets the URL from the query string
    url = (request.args.get("url") or "").strip()

    # Rejects the request if no URL was provided
    if not url:
        return jsonify({
            "service": "PhishStats",
            "error": True,
            "details": "missing url"
        }), 400

    try:
        # Parses the URL and extracts the hostname
        parsed = urlparse(url)
        host = parsed.netloc.lower().strip()

        # Rejects invalid URLs that do not contain a hostname
        if not host:
            return jsonify({
                "service": "PhishStats",
                "error": True,
                "details": "invalid url"
            })

        # Sends a request to the PhishStats API
        resp = requests.get(
            "https://api.phishstats.info/api/phishing",
            params={
                "_where": f"(url,like,{host})",
                "_sort": "-date",
                "_size": 5,
            },
            headers={
                "Accept": "application/json",
                "User-Agent": "ThreatCheck/1.0",
            },
            timeout=4,
        )

        # Handles non-success HTTP responses
        if resp.status_code != 200:
            return jsonify({
                "service": "PhishStats",
                "error": True,
                "details": f"HTTP {resp.status_code}"
            })

        # Reads the JSON response
        data = resp.json()

        # Checks whether any phishing records were found
        found = isinstance(data, list) and len(data) > 0

        # Returns a structured result to the frontend
        return jsonify({
            "service": "PhishStats",
            "safe": not found,
            "disposition": "phishing" if found else "clean",
            "brand": data[0].get("title", "N/A") if found else "N/A",
            "resolved": found,
            "records": data[:5] if found else []
        })

    except requests.exceptions.Timeout:
        # Handles request timeout
        return jsonify({
            "service": "PhishStats",
            "error": True,
            "details": "Service timed out"
        })

    except requests.exceptions.RequestException as e:
        # Handles request-related errors
        return jsonify({
            "service": "PhishStats",
            "error": True,
            "details": f"Request failed: {str(e)}"
        })

    except Exception as e:
        # Handles unexpected errors
        traceback.print_exc()
        return jsonify({
            "service": "PhishStats",
            "error": True,
            "details": str(e)
        })


@phishing_bp.route("/api/checkphish", methods=["POST"])
def api_checkphish():
    """
    Sends a URL to the CheckPhish service and polls until the scan is finished.

    Request body:
    - JSON containing a "url" field

    Returns:
    - a structured JSON result showing the CheckPhish verdict,
      brand, final URL, insights, and other details
    """
    # Reads JSON request data
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    # Rejects the request if no URL was provided
    if not url:
        return jsonify({
            "service": "CheckPhish",
            "error": True,
            "details": "missing url"
        }), 400

    # Rejects the request if the API key is not configured on the server
    if not CHECKPHISH_API_KEY:
        return jsonify({
            "service": "CheckPhish",
            "error": True,
            "details": "missing CHECKPHISH_API_KEY on server"
        }), 500

    try:
        # Submits the URL to the CheckPhish scan API
        submit_resp = requests.post(
            "https://developers.checkphish.ai/api/neo/scan",
            json={
                "apiKey": CHECKPHISH_API_KEY,
                "urlInfo": {"url": url}
            },
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

        # Handles non-success submission responses
        if submit_resp.status_code != 200:
            return jsonify({
                "service": "CheckPhish",
                "error": True,
                "details": f"submit failed HTTP {submit_resp.status_code}"
            })

        # Reads the submission response
        submit_data = submit_resp.json()
        job_id = submit_data.get("jobID")

        # Stops if no job ID was returned
        if not job_id:
            return jsonify({
                "service": "CheckPhish",
                "error": True,
                "details": "missing jobID"
            })

        # Polls the CheckPhish status endpoint until the scan is done
        for _ in range(15):
            time.sleep(2)

            status_resp = requests.post(
                "https://developers.checkphish.ai/api/neo/scan/status",
                json={
                    "apiKey": CHECKPHISH_API_KEY,
                    "jobID": job_id,
                    "insights": True
                },
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            # Handles non-success polling responses
            if status_resp.status_code != 200:
                return jsonify({
                    "service": "CheckPhish",
                    "error": True,
                    "details": f"status failed HTTP {status_resp.status_code}"
                })

            # Reads the current scan status
            status_data = status_resp.json()

            # If the scan has finished, return the final result
            if status_data.get("status") == "DONE":
                disposition = (status_data.get("disposition") or "unknown").lower()
                return jsonify({
                    "service": "CheckPhish",
                    "safe": disposition == "clean",
                    "disposition": status_data.get("disposition", "Unknown"),
                    "brand": status_data.get("brand", "N/A"),
                    "resolved": status_data.get("resolved", False),
                    "jobID": job_id,
                    "insights": status_data.get("insights"),
                    "finalURL": status_data.get("url"),
                    "screenshotPath": status_data.get("screenshot_path"),
                    "raw": status_data
                })

        # If polling ends without a finished result, return a timeout error
        return jsonify({
            "service": "CheckPhish",
            "error": True,
            "details": "Scan timeout - results not available"
        })

    except requests.exceptions.Timeout:
        # Handles request timeout
        return jsonify({
            "service": "CheckPhish",
            "error": True,
            "details": "Service timed out"
        })

    except requests.exceptions.RequestException as e:
        # Handles request-related errors
        return jsonify({
            "service": "CheckPhish",
            "error": True,
            "details": f"Request failed: {str(e)}"
        })

    except Exception as e:
        # Handles unexpected errors
        traceback.print_exc()
        return jsonify({
            "service": "CheckPhish",
            "error": True,
            "details": str(e)
        })