# Project: IssueToPR (AI Pull Request Pipeline)

## Tech Stack
- **Language**: Python 3.11+ (Strict type hinting)
- **Architecture**: LangGraph (StateGraph pipeline)
- **Web API**: FastAPI (Webhook listener)
- **Background Tasks**: Celery with Redis broker
- **Infrastructure**: Docker & Docker Compose (API + Worker containers)
- **Security Tools**: Semgrep, Bandit, pip-audit, detect-secrets
- **LLM Provider**: OpenAI (GPT-4o)

## Commands
- **Run the Stack**: `docker-compose up --build -d`
- **View Worker Logs**: `docker-compose logs -f worker`
- **View API Logs**: `docker-compose logs -f api`
- **Expose Webhook**: `ngrok http 8000`

## Code Conventions
- **Strict Typing**: Use Python 3.10+ type hints (`list[str]`, `str | None`).
- **Structured Logging**: Use `structlog`. Follow the pattern: `log.info("action_event", key=value)`.
- **LangGraph State**: All graph nodes take `PipelineState` and return a modified `PipelineState` dict. Do not mutate the state destructively without returning the proper dictionary.
- **Pydantic**: Use Pydantic models (located in `shared/models.py`) for all structured data (CodePlans, ScanResults, Findings).
- **Error Handling**: Nodes should handle their own exceptions. Return `{**state, "pipeline_error": str(exc), "should_abort": True}` only for unrecoverable errors.

## Architecture Boundaries
1. **API Container**: ONLY handles incoming GitHub Webhooks, verifies HMAC signatures, and queues Celery tasks. Do not put heavy processing here.
2. **Worker Container**: Executes the LangGraph pipeline and runs local shell commands (Node.js builds, Python scanners).
3. **Tools vs. Agents**: 
   - `tools/`: Dumb wrappers around external APIs (GitHub, LLMs) or shell commands.
   - `agents/`: Smart business logic that uses tools to modify the `PipelineState`.

## Critical Context
- The `Dockerfile` includes **Node.js 20.x** to allow the `build_agent` to verify JavaScript/Next.js builds locally before opening a PR.
- Always strip Markdown fences (````) from LLM code generation outputs, as the models frequently hallucinate them despite system prompts. This logic lives in `tools/llm_client.py`.
- **LangGraph Routing**: The pipeline supports self-healing loops (e.g., `build_verification` loops back to `codegen` up to 3 times on failure).
