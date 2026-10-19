# Click Shield — running and deploying

Two images make up the application. The same images run locally and on AWS:

| Image | Built from | Roles |
|---|---|---|
| `clickshield-backend` | `backend/Dockerfile` | `api` (default), `worker`, `migrate` (selected by the container command, see `backend/docker/entrypoint.sh`) |
| `clickshield-frontend` | `clickshield-frontend/Dockerfile` | nginx serving the dashboard build, proxying `/api/*` to the API |

PostgreSQL and Redis are compose services locally and managed services (RDS, ElastiCache) on AWS.

---

## 1. Run locally with Docker Compose

From the repository root:

```bash
docker compose up --build
```

| URL | What |
|---|---|
| http://localhost:8080 | Dashboard (nginx → `/api` proxied to the backend) |
| http://localhost:8000/health | API health |
| http://localhost:8000/api/v1/tracking.js | Tracking script (`/api/v1/track` is on the same port) |
| localhost:5432 / localhost:6379 | PostgreSQL / Redis, for local tools |

On start the backend runs `alembic upgrade head`, then serves the API. The worker waits until the backend is healthy, which means the schema is migrated.

**How protection runs.** When a session's verdict becomes FRAUD (see "Fraud engine" below), the API queues an IP exclusion in the same database transaction. After the commit it pushes a `process_action` job to Redis. The worker (`arq app.workers.arq_worker.WorkerSettings`) calls Google Ads.

A sweep every `WORKER_SWEEP_SECONDS` (default 15) also:
- runs due retries;
- re-queues actions from a crashed worker;
- picks up any action whose job push was lost, for example while Redis was down;
- promotes campaign overflow queues when the IP exclusion limit frees up.

Set `AUTO_PROTECTION_ENABLED=false` for detect-and-report only.

**Fraud engine.** Each tracking batch is scored by rules. Each rule has a category: NETWORK, REPUTATION, VELOCITY, BEHAVIOR, AUTOMATION, GEO or ANOMALY.
- **Risk:** rules in the same category add up with diminishing returns, and each category has a cap.
- **Signal diversity:** the number of independent categories that contributed.
- **Confidence:** how sure the engine is of the verdict.

The verdict comes from the organization's protection mode:

| Verdict | Means | Action |
|---|---|---|
| SAFE | allow | none |
| MONITOR | watch | none |
| FLAG | needs review | shown in the Sessions "Needs review" filter, never excluded automatically |
| FRAUD | block | IP exclusion queued |

Mode thresholds (Conservative / Balanced / Aggressive / Custom) are set by `PROTECTION_MODE_POLICIES`. Owners and admins change the mode on the Settings page.

**Rules and tuning.** Rule weights and thresholds live in the `rules` table, which migrations seed. Per-organization overrides are made on the Settings page (`/api/v1/rules`). Every change is audited.

**Rollback switches** (environment variables, no deploy needed):
- `SCORING_VERSION=1`: the old sum / average scoring and the 80/80 decision.
- `RULES_SOURCE=code`: ignore the database and use the built-in rule catalog.

**Anomaly detection.** The worker runs `anomaly_detection` every 5 minutes. It builds hourly per-campaign traffic statistics and compares them with a 14-day median/MAD baseline. It records click spikes, sudden fast clicking and traffic drops, and audits HIGH anomalies as `TRAFFIC_ANOMALY_DETECTED`. Campaigns with less than 7 days of traffic are skipped. `ANOMALY_DETECTION_ENABLED=false` turns it off.

**Websites and tracking.** Add a website on the Websites page, paste the snippet (`<script async src=".../track.js" data-site-id="...">`), then open the site once. The first event from the website's own domain verifies it. Events from other domains are rejected (`TRACKING_ENFORCE_ORIGIN`, which can also be turned off per website). Token rotation invalidates the old token immediately. The tracker's tests run with `node --test backend/tests/js/tracker.test.mjs`. `frontend/test-site.html` produces every event type.

**Alerts.** Google failures, expired Google access, exclusion limits, fraud spikes, unusual traffic, silent websites, foreign-origin token use and API errors open alerts. Repeats of the same problem count on one alert. Alerts appear in the dashboard, with a sidebar badge and a banner for critical ones, and are emailed to owners and admins, at most once per alert every `ALERT_EMAIL_THROTTLE_HOURS`. In development `EMAIL_BACKEND=console` logs the email. In production set `EMAIL_BACKEND=smtp` and `SMTP_*`.

**Data retention.** A daily job (03:15 UTC):
- deletes raw events after 30 days;
- anonymizes non-fraud sessions after 90 days and fraud sessions after 365 days;
- deletes audit logs after 730 days.

These are defaults, and organizations can override them in Settings. It starts with `RETENTION_DRY_RUN=true`: it only counts, and audits the counts as `RETENTION_RUN`. Review the counts, take a backup, then set `RETENTION_DRY_RUN=false`. Owners can erase one visitor's data in Settings.

**Configuration.** Compose reads `backend/.env` if it exists (Google OAuth client ID/secret, keys, …). Start from `backend/.env.example`. The database, Redis, CORS and proxy settings are set in `docker-compose.yml` and override `.env`, so a `.env` written for running on the host (with `localhost` URLs) still works. Without Google credentials, set `GOOGLE_ADS_DRY_RUN=true` in `backend/.env`; otherwise protection actions fail with "Google Ads is not configured".

**Connecting Google Ads (OAuth).** Google redirects the browser to a dashboard route, `GOOGLE_OAUTH_REDIRECT_URI` (default `http://localhost:8080/google/callback`). The dashboard then posts the `code` and `state` to `POST /api/v1/google/complete` with the user's Bearer token. The API checks that the state was started by that same user and organization before it saves anything (SEC-01). Register the redirect URI exactly in Google Cloud; with `npm run dev` use `http://localhost:5173/google/callback` instead. The old `GET /api/v1/google/callback` no longer exchanges codes: it redirects to `/google` with an error.

Useful commands:

```bash
docker compose logs -f backend worker          # follow API + worker logs
docker compose run --rm backend migrate         # run migrations only
docker compose run --rm backend alembic history # any one-off command
docker compose up db redis                      # infra only; run uvicorn / vite on the host
docker compose down                             # stop (data kept)
docker compose down -v                          # stop and DELETE the database volume

# Operator commands (python -m app.cli --help)
docker compose run --rm backend python -m app.cli create-admin --email owner@client.com --organization "Client"
docker compose run --rm backend python -m app.cli grant-platform-admin --email staff@clickshield.com
docker compose run --rm backend python -m app.cli reencrypt-tokens     # after adding a new key first in TOKEN_ENCRYPTION_KEYS
docker compose run --rm backend python -m app.cli retention            # dry run now (add --apply to delete)
```

The development seed (`ENVIRONMENT=development` only) creates `DEFAULT_ADMIN_EMAIL`. Without `DEFAULT_ADMIN_PASSWORD` it generates a password and logs it once. Platform staff see the **Admin** page (health, tenants, failed actions with retry, global rules, audit) only after `grant-platform-admin`.

**Tests.** From `backend/` with the dev requirements installed (`pip install -r requirements-dev.txt`):

```bash
docker compose up -d db          # from the repo root: a PostgreSQL for database tests
pytest                           # everything: unit, tests/db, tests/poc (spec §75 scenarios)
pytest tests/poc                 # only the 7 POC scenarios
```

Database tests use `TEST_DATABASE_URL` (default `postgresql+asyncpg://postgres:postgres@localhost:5432/clickshield_test`). They create and migrate that database themselves and truncate it before every test, so its name must end in `_test`. Your dev database is never touched. Without a reachable PostgreSQL, database tests are skipped. CI runs the same suite on every PR (`.github/workflows/backend-tests.yml`).

**Existing local data.** The old `backend/docker-compose.yml` ran as project `backend`, so its data is in the volume `backend_clickshield_pgdata`. The new stack uses `clickshield_pgdata`. To keep the old data, copy it once before the first `up`:

```bash
docker volume create clickshield_pgdata
docker run --rm -v backend_clickshield_pgdata:/from -v clickshield_pgdata:/to alpine sh -c "cp -a /from/. /to/"
```

---

## 2. Deploy on AWS (target layout)

```
                Route 53 ─► ALB (HTTPS, ACM certificate)
                              │
               ┌──────────────┴──────────────┐
          /api/* , /health              everything else
               │                              │
     ECS service "api"               ECS service "frontend"
     clickshield-backend (api)       clickshield-frontend (nginx)
               │
     ECS service "worker"  ── clickshield-backend (worker), no load balancer
               │
     RDS PostgreSQL 16  ·  ElastiCache Redis 7  ·  Secrets Manager  ·  CloudWatch Logs
```

All three ECS services run on Fargate in private subnets. Only the ALB is public. The frontend can alternatively be served from S3 + CloudFront (upload `dist/`), with `/api/*` routed to the ALB.

### 2.1 Build and push images (ECR)

```bash
AWS_REGION=us-east-1
REGISTRY=<account-id>.dkr.ecr.$AWS_REGION.amazonaws.com
TAG=$(git rev-parse --short HEAD)

aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $REGISTRY

docker build --platform linux/amd64 -t $REGISTRY/clickshield-backend:$TAG backend
docker build --platform linux/amd64 -t $REGISTRY/clickshield-frontend:$TAG clickshield-frontend
docker push $REGISTRY/clickshield-backend:$TAG
docker push $REGISTRY/clickshield-frontend:$TAG
```

Use `--platform linux/arm64` instead for Graviton tasks.

### 2.2 ECS services

| Service | Image / command | Port | Health check | Desired count |
|---|---|---|---|---|
| `api` | backend, `["api"]` | 8000 | ALB target group: `GET /health/ready` (database reachable); `/health/live` for liveness | 2+ (OAuth state and rate limits live in Redis) |
| `worker` | backend, `["worker"]` (arq) | — | container: `arq --check app.workers.arq_worker.WorkerSettings` | 1 (more is safe: jobs and sweeps claim actions with row locks) |
| `frontend` | frontend (default) | 80 | ALB target group: `GET /healthz` | 1–2 |

ALB rules: `/api/*` and `/health` → `api` target group; default → `frontend` target group. With path routing at the ALB, the frontend's own `/api` proxy isn't used. Set `BACKEND_UPSTREAM` to the API's internal address only if you want nginx to proxy instead.

Log configuration: `awslogs` driver for every container. The images log to stdout (`LOG_TO_FILE=false` is the image default).

### 2.3 Configuration

Secrets (Secrets Manager / SSM, injected through the task definition `secrets` block):

| Variable | Notes |
|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://USER:PASS@<rds-endpoint>:5432/clickshield` |
| `DATABASE_URL_SYNC` | `postgresql+psycopg://USER:PASS@<rds-endpoint>:5432/clickshield` (Alembic) |
| `SECRET_KEY` | JWT signing key, at least 32 random bytes: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `TOKEN_ENCRYPTION_KEYS` | Fernet keys for Google refresh tokens, comma-separated, newest first: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth client of the Google Cloud project |
| `SMTP_USER` / `SMTP_PASSWORD` | alert and invitation email (with `EMAIL_BACKEND=smtp`, `SMTP_HOST`) |
| `IPINFO_API_KEY` | optional, IP intelligence |

Outside `ENVIRONMENT=development` the API **refuses to start** if:
- `SECRET_KEY` is missing or shorter than 32 bytes;
- no `TOKEN_ENCRYPTION_KEYS` is set, or a key is invalid;
- a secret equals a value that was once committed to this repository;
- `GOOGLE_CLIENT_ID` is set without `GOOGLE_CLIENT_SECRET`;
- `API_CORS_ORIGINS` contains `*`.

Nothing is seeded outside development: create the first owner with `python -m app.cli create-admin`.

**Key rotation.**
1. Deploy with `TOKEN_ENCRYPTION_KEYS=new,old`.
2. Run `python -m app.cli reencrypt-tokens`.
3. Deploy with `TOKEN_ENCRYPTION_KEYS=new`.

Rotating `SECRET_KEY` signs everyone out.

Plain environment variables:

| Variable | Value |
|---|---|
| `ENVIRONMENT` | `production` |
| `REDIS_URL` | `rediss://<elasticache-endpoint>:6379/0` |
| `TRUSTED_PROXY_CIDRS` | the VPC CIDR (the ALB's nodes), e.g. `10.0.0.0/16`, so client IPs come from the ALB's `X-Forwarded-For` (task 001) |
| `FRONTEND_APP_URL` | `https://app.example.com` |
| `GOOGLE_OAUTH_REDIRECT_URI` | `https://app.example.com/google/callback` — a **dashboard** route (served by the frontend, not the API). The dashboard posts the code to `/api/v1/google/complete`. Register exactly this URI in Google Cloud. |
| `API_CORS_ORIGINS` | `https://app.example.com` |
| `TRACKING_SNIPPET_BASE_URL` | public base URL that serves `/track.js` (the snippet's script) |
| `RUN_MIGRATIONS` | `true` on `api` (see below); not used by `worker` |
| `UVICORN_WORKERS` | `1` per task (scale with more tasks) |
| `EMAIL_BACKEND` / `SMTP_HOST` / `ALERT_FROM_EMAIL` | `smtp`, your SMTP relay (e.g. SES SMTP), sender address |
| `RETENTION_DRY_RUN` | `true` until the first counts are reviewed (see §1 "Data retention") |
| Rate limits | `TRACKING_RATE_LIMIT_PER_MINUTE` (per IP, 300), `TRACKING_RATE_LIMIT_PER_SITE_PER_MINUTE`, `LOGIN_*`, `REGISTER_RATE_LIMIT_PER_IP_PER_HOUR`, `API_RATE_LIMIT_PER_USER_PER_MINUTE`; Redis-backed, fail open |

### 2.4 Database migrations

The `api` container runs `alembic upgrade head` before it starts serving. It retries while the database is unreachable (`MIGRATION_MAX_ATTEMPTS`, default 10). Migrations take a PostgreSQL advisory lock (`backend/alembic/env.py`), so several API tasks starting together migrate one at a time.

For production, the recommended setup is to run migrations as a separate step of the deploy pipeline and turn them off in the service:

```bash
aws ecs run-task --cluster clickshield --task-definition clickshield-api \
  --overrides '{"containerOverrides":[{"name":"api","command":["migrate"]}]}' ...
# then deploy services with RUN_MIGRATIONS=false
```

The ALB health-check grace period must cover migration time when `RUN_MIGRATIONS=true`.

### 2.5 Known limits before scaling or going live

- **Rotate anything that ran with committed secrets.** Any environment that ever used the old committed `SECRET_KEY` or Fernet key must get new values. Follow the key rotation steps above, and remove the old seeded `admin@gmail.com` user if it exists.
- **Dashboard tokens in `localStorage`.** The dashboard still keeps its JWTs in `localStorage`. Moving the refresh token to an `HttpOnly` cookie is a follow-up (task 032, optional part).
- **In-process metrics.** The health page's scoring-latency and error-rate figures come from the API process that answers. Prometheus export would aggregate them across tasks.
- **Real Google and real browsers.** The Google Ads calls (tasks 002, 018, 033) and real-browser tracker checks (task 024) still need a Google Ads test account and Safari, mobile and headless runs.

Infrastructure as code (Terraform / CDK) for the layout above isn't included yet.
