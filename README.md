# IssueToPR 🤖🚀

An advanced, AI-powered automated pipeline built with **LangGraph** that listens to GitHub issues via webhooks, writes code to fix them, runs comprehensive security and static analysis scans, auto-fixes vulnerabilities, and submits a detailed Pull Request.

## 🌟 How it Works

When a GitHub issue is labeled with a specific trigger (e.g., `ai-autofix`), the webhook listener (FastAPI) receives the event and enqueues a job into Redis. A Celery worker then processes the job through an **8-Agent LangGraph Pipeline**.

### The 8-Agent Pipeline

The state machine wires together 8 specialized agents that run sequentially. Each node handles errors gracefully:

1. **🕵️‍♂️ IssueAnalyzer Agent (`node_analyze_issue`)**
   - Reads the GitHub issue title and body.
   - Produces a structured `CodePlan` outlining the files to change and the approach.
   - Creates a new git branch on the repository.

2. **💻 Codegen Agent (`node_codegen`)**
   - Takes the `CodePlan` and uses OpenAI to generate the actual code fixes.
   - Commits the new code directly to the created branch.

3. **🔍 Scan Agent (`node_scan`)**
   - Runs static analysis on the modified codebase.
   - Uses **Ruff** for linting and code quality.
   - Uses **Bandit** to find common security issues in Python code.

4. **🛡️ Security Agent (`node_security`)**
   - Performs deep security scanning.
   - Uses **Semgrep** (with optional Pro rules) for advanced static application security testing (SAST).
   - Runs OWASP regex checks.
   - Uses **detect-secrets** to ensure no API keys or credentials were leaked in the generated code.

5. **📦 Dependency Audit Agent (`node_dep_audit`)**
   - Scans project dependencies for known vulnerabilities (CVEs).
   - Uses **pip-audit** to ensure the project is secure at the package level.

6. **⚖️ RiskScorer Agent (`node_risk_score`)**
   - Aggregates all findings from the Scan, Security, and DepAudit agents.
   - Computes a weighted **Risk Score** (0-100) based on the severity of the findings and the number of files changed.

7. **🔧 AutoFix Agent (`node_autofix`)**
   - Reviews the CRITICAL and HIGH severity findings identified by the scanners.
   - Automatically writes and commits secondary fixes to patch these newly discovered vulnerabilities before the PR is opened.

8. **📤 PRCreator Agent (`node_create_pr`)**
   - Gathers all the data, the risk score, and the scan results.
   - Opens a GitHub Pull Request with a beautifully formatted markdown summary.
   - If the risk score exceeds the `RISK_SCORE_DRAFT_THRESHOLD`, the PR is opened as a **Draft** requiring human review.
   - Posts a comment back on the original issue linking to the new PR.

---

## 🛠️ Technology Stack

- **Framework:** [LangGraph](https://python.langchain.com/v0.1/docs/langgraph/) for state machine orchestration.
- **LLM:** OpenAI (GPT-4o) for code generation and analysis.
- **API/Webhooks:** FastAPI + Uvicorn.
- **Task Queue:** Celery + Redis.
- **Deployment:** Docker & Docker Compose.
- **Security Tools:** Ruff, Bandit, Semgrep, detect-secrets, pip-audit.

---

## 🚀 Getting Started

### Prerequisites
- Docker and Docker Compose
- Python 3.11+
- An OpenAI API Key
- A GitHub Personal Access Token (Classic) with `repo` and `workflow` scopes.

### 1. Configuration
Copy the environment template and fill in your keys:
```bash
cp .env.example .env
```
Make sure to set your `GITHUB_WEBHOOK_SECRET` and `GITHUB_ISSUE_LABEL` (e.g., `ai-autofix`).

### 2. Run the Services
Start the API, Redis, and the Celery worker using Docker Compose:
```bash
docker-compose up --build -d
```
*(Run `docker-compose logs -f worker` to watch the AI agents work in real-time).*

### 3. Setup GitHub Webhooks
Use a tool like `ngrok` to expose your local port `8000`:
```bash
ngrok http 8000
```
1. Go to your GitHub Repository Settings → Webhooks.
2. Add your ngrok URL `https://<your-ngrok-url>/webhook/issue`.
3. Set Content type to `application/json`.
4. Paste your `GITHUB_WEBHOOK_SECRET`.
5. Select **Let me select individual events** and check **Issues** ONLY.

---

## 🤝 How to Contribute

We welcome contributions to make the agents smarter and the pipeline more robust!

### Development Workflow
1. **Fork the repository** and clone it locally.
2. **Create a new branch** for your feature or bugfix:
   ```bash
   git checkout -b feature/amazing-new-agent
   ```
3. **Make your changes**. If you are adding a new scanning tool, add it as a new node in `pipeline/graph.py` and update the `PipelineState`.
4. **Test your changes** locally using the webhook payload simulator.
5. **Commit your changes** with descriptive commit messages.
6. **Push to your fork** and submit a **Pull Request** to the `main` branch.

### Areas for Contribution
- **New Agents:** Add support for Node.js (npm audit, ESLint) or Go static analysis.
- **Better Prompts:** Improve the `codegen` agent's system prompt for better code quality.
- **Testing:** Add `pytest` unit tests for the individual graph nodes.

---
*Built with ❤️ and LangGraph.*
