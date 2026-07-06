# Security Findings Translator

Translate technical security findings from AWS GuardDuty, Security Hub, Nessus, and CVEs into clear, audience-appropriate language using AI — with smarter risk scoring than CVSS alone.

![License](https://img.shields.io/badge/license-MIT-blue)
![Tests](https://img.shields.io/badge/tests-32%20passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

---

## The Problem

Security tools generate findings that are technically accurate but practically useless to most people who need to act on them.

A GuardDuty alert reading `UnauthorizedAccess:EC2/SSHBruteForce` means nothing to a CFO deciding whether to approve emergency remediation budget. A Nessus report means nothing to a developer who just needs to know what to fix. The finding sits unread, unactioned, and the vulnerability stays open.

This tool closes that gap.

---

## What Makes This Different

Most vulnerability tools stop at a CVSS score — a theoretical severity rating that doesn't account for whether anyone is actually exploiting the vulnerability right now. This tool combines three signals:

| Signal | What it measures | Source |
|---|---|---|
| **CVSS** | Theoretical worst-case severity | NVD |
| **EPSS** | Probability of exploitation in the next 30 days | FIRST.org (updated daily) |
| **CISA KEV** | Confirmed active exploitation by real attackers | CISA Known Exploited Vulnerabilities |

A CVSS 9.8 finding with 0.1% EPSS is far less urgent than a CVSS 6.5 finding actively being exploited in the wild — but a CVSS-only scanner can't tell you that. This tool can.

**The KEV floor:** Any vulnerability on the CISA KEV list is floored at a minimum **High** risk rating (8.0/10), regardless of environment context. Real-world active exploitation is never discounted away.

---

## Who It's For

Each finding can be translated for 7 different audiences:

| Audience | What they get |
|---|---|
| **Executive** | Business impact, financial exposure, board-level language |
| **Manager** | Sprint priority, effort estimate, team ownership |
| **Developer** | Root cause, exact code/Terraform/CLI fix, testing steps |
| **Security Analyst** | MITRE ATT&CK mapping, IOCs, detection queries |
| **SOC Analyst** | Triage steps, containment actions, escalation criteria |
| **DevSecOps** | IaC fixes, CI/CD pipeline integration points |
| **GRC** | Compliance mapping (SOC 2, ISO 27001, PCI DSS, HIPAA, NIST CSF) |

---

## Supported Input Formats

- AWS GuardDuty JSON
- AWS Security Hub ASFF (Amazon Findings Format)
- Tenable Nessus JSON
- Generic JSON or CSV

---

## Quick Demo (No Setup Required)

Want to see it in action first? Run the web app with Docker — one command:

```bash
git clone https://github.com/DanielSantiagoSec/security-findings-translator.git
cd security-findings-translator
cp .env.example .env
# Add your Gemini API key to .env
docker compose up
```

Then open `http://localhost:3000` in your browser.

---

## Full Setup — Web App (Recommended)

The web app gives you a full dashboard with upload, risk scoring, and AI translation in your browser.

### Step 1 — Prerequisites

You need these installed before starting:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) — runs the entire stack
- [Git](https://git-scm.com/downloads) — to clone the repo
- A free [Google Gemini API key](https://aistudio.google.com) — no credit card required

**How to get a free Gemini API key:**
1. Go to [aistudio.google.com](https://aistudio.google.com)
2. Sign in with your Google account
3. Click **Get API key** → **Create API key**
4. Copy the key — you will need it in Step 3

### Step 2 — Clone the Repository

```bash
git clone https://github.com/DanielSantiagoSec/security-findings-translator.git
cd security-findings-translator
```

### Step 3 — Configure Your Environment

Copy the example environment file and add your API key:

```bash
cp .env.example .env
```

Open `.env` in any text editor and fill in:

```
GEMINI_API_KEY=your-gemini-api-key-here
SECRET_KEY=any-long-random-string-you-make-up
```

Everything else can stay as the default for local use.

> **Windows users:** If you are on Windows, use WSL (Windows Subsystem for Linux) for the best experience. Open the Microsoft Store, install Ubuntu, then run all commands in the Ubuntu terminal.

### Step 4 — Start the Application

```bash
docker compose up
```

Wait until you see:
```
Application startup complete.
```

This takes about 60 seconds the first time while Docker downloads everything.

### Step 5 — Open the App

Go to `http://localhost:3000` in your browser.

1. Click **Register** and create an account
2. Click **+ Upload** and select one of the example files from `cli/examples/`
3. Click on a finding to see the risk scores
4. Select an audience tab and click **Translate**

### Stopping the App

Press `Ctrl+C` in the terminal where Docker is running.

To start again later:
```bash
docker compose up
```

---

## CLI Setup (Command Line Only)

If you prefer the command line or do not want Docker, use the CLI directly.

### Step 1 — Prerequisites

- Python 3.11 or newer — [download here](https://www.python.org/downloads/)
- A free [Google Gemini API key](https://aistudio.google.com)

Check your Python version:
```bash
python --version
```

### Step 2 — Clone and Install

```bash
git clone https://github.com/DanielSantiagoSec/security-findings-translator.git
cd security-findings-translator
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows (PowerShell)
.venv\Scripts\activate

# Mac/Linux/WSL
source .venv/bin/activate
```

Install dependencies:
```bash
pip install google-genai click rich pytest
```

### Step 3 — Set Your API Key

```bash
# Windows (PowerShell)
$env:GEMINI_API_KEY = "your-key-here"

# Mac/Linux/WSL
export GEMINI_API_KEY="your-key-here"
```

### Step 4 — Try the Example Files

**Score a finding without AI (free, instant):**
```bash
python -m cli.main finding cli/examples/guardduty_findings.json --score-only
```

**Translate a finding for an executive:**
```bash
python -m cli.main finding cli/examples/security_hub_log4shell.json --audience executive
```

**Translate for a developer with full details:**
```bash
python -m cli.main finding cli/examples/security_hub_log4shell.json --audience developer --verbose
```

**Run the interactive demo:**
```bash
python -m cli.main demo --audience executive
```

**All available audiences:**
```
executive | manager | developer | security_analyst | soc_analyst | devsecops | grc
```

### Step 5 — Use Your Own Findings

Export findings from your security tool and point the CLI at them:

```bash
# GuardDuty findings exported from AWS Console
python -m cli.main finding your-guardduty-export.json --audience developer

# Security Hub findings
python -m cli.main finding your-security-hub-export.json --audience executive

# Generic CSV
python -m cli.main finding your-findings.csv --audience manager
```

---

## Running the Tests

```bash
python -m pytest cli/tests/ -v
```

32 tests covering the parser layer and risk scoring engine. No API key required — tests run completely offline.

Expected output:
```
32 passed in 0.30s
```

---

## Project Structure

```
security-findings-translator/
├── cli/                             Command line interface
│   ├── main.py                      CLI entry point (click commands)
│   ├── src/
│   │   ├── models/finding.py        Core data models
│   │   ├── parsers/                 GuardDuty, Security Hub, Nessus, generic
│   │   ├── engines/
│   │   │   ├── risk_engine.py       EPSS + KEV + context scoring
│   │   │   └── translation_engine.py  AI translation via Gemini
│   │   ├── prompts/                 Per-audience system prompts
│   │   └── utils/formatter.py       Terminal output formatting
│   ├── examples/                    Sample finding files to test with
│   └── tests/                       32 unit tests
│
├── backend/                         FastAPI web backend
│   ├── api/v1/                      REST API endpoints
│   ├── models/                      Database models and schemas
│   ├── services/                    Business logic
│   └── config.py                    Configuration management
│
├── frontend/
│   └── public/index.html            Single-page web application
│
├── infrastructure/
│   └── docker/                      Dockerfile and nginx config
│
├── docker-compose.yml               Runs the full stack locally
├── .env.example                     Environment variable template
└── docs/
    └── RISK_SCORING_BUG_WRITEUP.md  Technical writeup of KEV floor bug
```

---

## Troubleshooting

**"Permission denied" on upload**
Make sure Docker has finished starting — wait for `Application startup complete` before uploading.

**"Rate limit exceeded" on translation**
The free Gemini tier allows 15 requests/minute and 1,500/day. Wait 60 seconds and try again, or enable billing in Google AI Studio for unlimited requests.

**"Invalid credentials" on login**
The database resets when you run `docker compose down -v`. Register a new account after a full restart.

**Windows: commands not working**
Use WSL (Windows Subsystem for Linux). Install Ubuntu from the Microsoft Store, then run all commands in the Ubuntu terminal.

**Port 3000 already in use**
Another app is using port 3000. Stop it, or change the port in `docker-compose.yml`.

---

## Security

This tool was built following OWASP Top 10 guidelines:

- Passwords hashed with bcrypt
- JWT authentication with token type verification
- Rate limiting on login (5/min) and registration (3/min)
- Timing-attack-safe login flow
- Project-level access control
- File upload type validation
- Non-root Docker container
- No secrets in source code — all credentials via environment variables
- Dependency audit: no known CVEs (`pip-audit` clean)

---

## Contributing

Contributions welcome. Please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run the tests (`python -m pytest cli/tests/ -v`)
5. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built by [Daniel Santiago](https://github.com/DanielSantiagoSec) — BsC Cybersecurity*
