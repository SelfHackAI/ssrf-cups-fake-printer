#!/usr/bin/env python3
from flask import Flask, request, jsonify
import re
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Sensitive data patterns (e.g., password, email, credit card information)
sensitive_patterns = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "password": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'\"]?([^\'\" ]+)[\'\"]?",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "api_key": r"(?i)(?:api_key|api_token|key)\s*[:=]\s*[\'\"]?([^\'\" ]+)[\'\"]?"
}


def _normalize_matches(matches):
    """
    Normalize re.findall output: it can be list[str] or list[tuple].
    Return list of strings.
    """
    normalized = []
    for m in matches:
        if isinstance(m, tuple):
            # join tuple parts into a single string or pick first non-empty
            joined = " ".join([part for part in m if part])
            normalized.append(joined)
        else:
            normalized.append(m)
    return normalized


def extract_sensitive_data(data: str) -> dict:
    """Find sensitive information in the given data string."""
    if not isinstance(data, str):
        try:
            data = str(data)
        except Exception:
            data = ""
    extracted_data = {}
    for key, pattern in sensitive_patterns.items():
        try:
            matches = re.findall(pattern, data)
        except re.error:
            matches = []
        matches = _normalize_matches(matches)
        if matches:
            extracted_data[key] = matches
    return extracted_data


@app.route("/", methods=["POST", "GET"])
def receive_request():
    """Analyze the HTTP request received from the printer server."""

    # Get the IP address of the requester (fallback if None)
    client_ip = request.remote_addr or "unknown"

    # Get request headers (convert to regular dict)
    try:
        headers = dict(request.headers)
    except Exception:
        headers = {}

    # Read request body safely
    if request.method == "POST":
        # Try JSON first (common), then raw text
        data = ""
        try:
            json_body = request.get_json(silent=True)
            if json_body is not None:
                data = str(json_body)
            else:
                # get_data(as_text=True) decodes using charset if present
                data = request.get_data(as_text=True)
        except Exception:
            try:
                data = request.data.decode("utf-8", errors="ignore")
            except Exception:
                data = "<unreadable>"
        logging.info("Received POST data (IP: %s): %s", client_ip, (data if len(data) < 2000 else data[:2000] + "..."))
    else:
        # Get GET parameters as a reproducible string
        try:
            params = request.args.to_dict(flat=False)
            data = str(params)
        except Exception:
            data = ""
        logging.info("Received GET data (IP: %s): %s", client_ip, data)

    # Extract sensitive data from headers and data content
    sensitive_data = extract_sensitive_data(data)
    sensitive_headers = extract_sensitive_data(str(headers))

    # Construct response (keep it simple and JSON-serializable)
    response = {
        "client_ip": client_ip,
        "headers": headers,
        "sensitive_data": sensitive_data,
        "sensitive_headers": sensitive_headers,
    }

    logging.info("Request analyzed (IP: %s): %s", client_ip, {k: (v if k != "headers" else "<headers>") for k, v in response.items()})

    return jsonify(response), 200


if __name__ == "__main__":
    # Run only in trusted, isolated lab environments
    # Listening on 0.0.0.0:8080 to accept CUPS outbound requests from other VMs/hosts
    app.run(host="0.0.0.0", port=8080)
