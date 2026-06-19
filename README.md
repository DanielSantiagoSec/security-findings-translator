\# Security Findings Translator



Translate technical security findings — AWS GuardDuty, Security Hub, Nessus, CVEs — into clear, audience-appropriate language using AI. Built for security analysts, developers, engineering managers, and executives who all need to understand the same finding differently.



\## The problem



Security tools generate findings that are technically accurate but practically useless to most of the people who need to act on them. A GuardDuty alert reading `UnauthorizedAccess:EC2/SSHBruteForce` means nothing to a CFO deciding whether to approve emergency remediation budget. This tool closes that gap.



\## What makes this different from a standard CVSS scanner



Most vulnerability tools stop at a CVSS score — a theoretical severity rating that doesn't account for whether anyone is actually exploiting the vulnerability in the real world. This tool combines three signals instead of one:



| Signal | What it measures | Source |

|---|---|---|

| \*\*CVSS\*\* | Theoretical worst-case severity | NVD |

| \*\*EPSS\*\* | Real-world probability of exploitation in the next 30 days | FIRST.org (updated daily) |

| \*\*CISA KEV\*\* | Is this being actively exploited right now | CISA Known Exploited Vulnerabilities catalog |



A CVSS 9.8 finding with 0.1% EPSS and no KEV entry is far less urgent than a CVSS 6.5 finding that's actively being exploited in the wild — but a CVSS-only scanner can't tell you that. This tool can.



On top of that, every finding is scored with context: is the asset internet-facing, does it handle sensitive data, what environment is it in (prod vs. dev). A finding actively exploited in the wild (CISA KEV) is floored at a minimum "High" risk rating regardless of environment uncertainty, since real-world exploitation never gets discounted away.



\## What it does



1\. \*\*Parses\*\* findings from AWS GuardDuty, AWS Security Hub (ASFF format), Tenable Nessus, or generic JSON/CSV

2\. \*\*Scores risk\*\* using EPSS + CISA KEV + asset context, not just CVSS

3\. \*\*Translates\*\* each finding into one of seven audience-specific formats using AI:

&#x20;  - Executive — business impact, financial exposure, board-level language

&#x20;  - Manager — sprint priority, effort estimate, team ownership

&#x20;  - Developer — root cause, exact code/Terraform/CLI fix, testing steps

&#x20;  - Security Analyst — MITRE ATT\&CK mapping, IOCs, detection queries

&#x20;  - SOC Analyst — triage steps, containment actions, escalation criteria

&#x20;  - DevSecOps — IaC fixes, CI/CD pipeline integration points

&#x20;  - GRC — compliance framework mapping (SOC 2, ISO 27001, PCI DSS, HIPAA, NIST CSF)



\## Quickstart



\### Prerequisites

\- Python 3.11+

\- A free \[Google Gemini API key](https://aistudio.google.com) (no credit card required)



\### Setup



```bash

git clone https://github.com/DanielSantiagoSec/security-findings-translator.git

cd security-findings-translator

python -m venv .venv

.venv\\Scripts\\activate          # Windows

pip install google-genai click rich pytest

```



\### Set your API key



```bash

$env:GEMINI\_API\_KEY = "your-key-here"      # Windows PowerShell

export GEMINI\_API\_KEY="your-key-here"       # Mac/Linux

```



\### Run the demo



```bash

python -m cli.main demo --audience executive

```



\### Translate a real finding



```bash

python -m cli.main finding cli\\examples\\security\_hub\_log4shell.json --audience developer --verbose

```



\### Risk-score only, no AI call



```bash

python -m cli.main finding cli\\examples\\guardduty\_findings.json --score-only

```



\## Running the tests



```bash

python -m pytest cli\\tests\\ -v

```



32 tests covering the parser layer and risk engine — no API key required.



\## Project structure



```

cli/

├── main.py                          CLI entry point

├── src/

│   ├── models/finding.py            Core data models

│   ├── parsers/                     GuardDuty, Security Hub, Nessus, generic

│   ├── engines/

│   │   ├── risk\_engine.py           EPSS + KEV + context scoring

│   │   └── translation\_engine.py    AI translation via Gemini

│   ├── prompts/audience\_prompts.py  Per-audience system prompts

│   └── utils/formatter.py           Terminal output formatting

├── examples/                        Sample finding files

└── tests/                           Unit tests

```



\## Roadmap



This CLI is phase 1 of a larger platform. Planned phases:



\- Web application (FastAPI + React) for upload and dashboard views

\- Live AWS Security Hub / GuardDuty pulling (no manual export needed)

\- Jira and ServiceNow ticket generation

\- Agentic remediation — auto-generate Terraform/K8s/IAM policy fixes



\## License



MIT

