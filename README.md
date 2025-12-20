# Personal Finance Dashboard

Full-stack sample showing a Flask API with Redis caching and a React dashboard for multi-user expense tracking. The backend is structured for easy decomposition into services and horizontal scaling.

## Quickstart
1) Backend
- Install deps: `cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- Run dev server (SQLite): `FLASK_APP=app.py flask --app app.py run --debug`
- Ensure Redis is available at `REDIS_URL` (defaults to `redis://localhost:6379/0`).

2) Frontend
- `cd frontend && npm install`
- `npm run dev` (Vite) then open the printed URL.

3) Flow
- Register or log in, add expenses, and pull AI spending tips once you have some data. Category summary is cached in Redis.

## Deploying with Redis (Render backend + Vercel frontend)
1) Provision Redis on Render: “New +” → “Redis” → create instance → copy the `REDIS_URL`.
2) Backend on Render:
   - Create a Web Service pointing to `backend/app.py`.
   - Set env vars: `REDIS_URL` (from step 1), `DATABASE_URL` (Postgres URI), `SECRET_KEY`, `JWT_SECRET_KEY`.
   - Build/run command: `pip install -r backend/requirements.txt && cd backend && gunicorn app:app`.
3) Frontend on Vercel:
   - Deploy from `frontend/`.
   - Set `VITE_API_BASE` to your Render backend URL.
4) Sanity check: after deploy, hit `/healthz`. Then log in, create expenses, call `/api/expenses/summary` twice—you should see faster responses on repeat calls if Redis is reachable.

## Backend architecture (kept beginner-friendly)
- Single Flask app factory (`backend/app.py`) that wires blueprints, JWT auth, Redis caching, and CORS in one place.
- Modules: `routes/` (auth, expenses, imports), `services/` (cache helper, mock bank client), `models.py` (User, Expense), `config.py` (env settings).
- Caching: expense summary stored in Redis (`CACHE_TTL_SECONDS` default 60s) with basic invalidation on writes.
- Mock bank ingestion: `/api/imports/mock` generates sample transactions and saves them as expenses.
- Auth: JWT tokens on register/login; routes use `@jwt_required`.
- Persistence: SQLite by default; swap `DATABASE_URL` for Postgres/MySQL when ready.

## Scalability notes
- Stateless app servers: JWT sessions; Redis for shared cache. Run multiple Flask instances behind a load balancer (NGINX/ALB/Ingress).
- Database: move to managed Postgres with read replicas for read-heavy workloads; add migrations (Alembic) and indices on `user_id`, `created_at`.
- Caching: expand Redis usage for frequently accessed aggregates and bank responses; add cache versioning and background refresh.
- Background work: offload bank imports to a worker queue (e.g., Celery/RQ) and expose webhooks/polling for sync status.
- Microservice path: split auth, expense ledger, and bank-ingestion services; use shared messaging (Kafka/SQS) for ingestion events.
- Observability: add request logging, tracing (OpenTelemetry), metrics on latency/cache hit rate, and per-endpoint SLIs.

## API surface
- `POST /api/auth/register` `{email, password}` -> `{access_token, user}`
- `POST /api/auth/login` `{email, password}` -> `{access_token, user}`
- `POST /api/expenses` `{category, description?, amount}` (auth)
- `GET /api/expenses` (auth) recent list
- `GET /api/expenses/summary` (auth, cached)
- `GET /api/expenses/insights` (auth, AI; requires `OPENAI_API_KEY`)

## Frontend
- Vite + React (`frontend/src/App.jsx`) with a dark dashboard: auth, expense entry, AI spending coach card, category pie, and recent expenses table.
- Configurable API base via `VITE_API_BASE` (defaults to `http://localhost:5000`).

## Next steps
- Add validation and better error surfaces; client-side form validation.
- Add Alembic migrations and seed data.
- Replace mock bank client with real provider SDK in `services/mock_bank.py` and secure secrets via env.
- Add tests (pytest for backend, Vitest/RTL for frontend) and CI to run lint/tests on pushes.
