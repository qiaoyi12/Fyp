# TriageAI 

An AI-assisted Security Operations Center (SOC) platform for network intrusion detection, alert triage, and incident management. Built as a Final Year Project.

## Overview

TriageAI ingests network traffic logs, uses a trained ML model to flag and score potential intrusions, and routes them through a role-based workflow (Admin → Manager → Analyst) for investigation and resolution. It also includes AI-assisted tooling — a ticket assignment agent, a read-only SOC chatbot, and an analyst-support agent — to help SOC staff triage faster.

**Dataset:** Based on CICIDS2018 network traffic data.

## Features

- **Role-Based Access Control (RBAC):** Three-tier permission system (Admin, Manager, Analyst) with role-scoped data access.
- **Alert Triage & Analysis:** Upload traffic logs (CSV) for automated ML-based classification, with severity scoring and confidence display.
- **Log Viewer:** Full-volume traffic log storage with server-side filtering, separate from the capped alerts table, with on-demand escalation to full alert records.
- **Ticket Assignment System:** Automated and manual assignment of alerts to analysts/managers, with per-analysis ticket numbering.
- **IP Blacklist Management:** Flag and track known malicious source IPs.
- **AI-Assisted Tools:**
  - Ticket assignment agent (deterministic assignment logic with LLM-generated captioning)
  - SOC chatbot (read-only, one-shot query assistant)
  - Analyst agent (one-shot support on pre-fetched context)
- **Demo Tooling:** Seed script for default accounts and a standalone live traffic simulator for demonstrations.

## Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite (session-based auth, no JWT)
- **ML:** scikit-learn and jupyter notebook (trained classifier + scaler for inference)
- **Frontend:** HTML/CSS/JS templates served via Flask

## Project Structure

```
Fyp/
├── agenticAI/          # Agent logic (assignment agent, chatbot, analyst agent)
├── backend/             # Core backend services, models, and business logic
│   └── src/services/
├── dataset/             # Training/reference datasets and saved model artifacts
│   └── zann_dataset/    # Includes scaler.pkl used at inference time
├── frontend/             # Static assets (CSS/JS) and templates
├── app.py                # Main Flask application entry point
├── create_users.py       # Seeds default demo accounts (run before first launch)
├── requirements.txt       # Python dependencies
└── .gitignore
```

## Getting Started

### Prerequisites

- Python 3.x
- pip

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/qiaoyi12/Fyp.git
   cd Fyp
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root with the following keys (see [Environment Variables](#environment-variables) below).

4. Seed the default demo accounts:
   ```bash
   python create_users.py
   ```

5. Run the application:
   ```bash
   python app.py
   ```

6. Open the app in your browser at `http://127.0.0.1:5000` (or your configured host/port).

## Environment Variables

Create a `.env` file in the project root with the following (values not included — request separately or generate your own):

```
SECRET_KEY=
OPENAI_API_KEY=
```

- `SECRET_KEY` — Flask session signing key. Generate one with:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- `OPENAI_API_KEY` — Used by the agentic AI components (chatbot, assignment captioning, analyst agent).

**Note:** `.env` is git-ignored and must never be committed.

## Roles

| Role    | Access                                                            |
|---------|--------------------------------------------------------------------|
| Admin   | Full system access, user management                                |
| Manager | Assign tickets, view team-wide alerts                              |
| Analyst | View and resolve assigned tickets only                             |

## Notes

- This is an academic Final Year Project and is not intended for production security use.
- The "agentic AI" components are intentionally scoped: most are one-shot or deterministic with LLM-assisted output, rather than fully autonomous multi-step agents. See the project report for a full breakdown.

## License

Academic project — no license specified.
