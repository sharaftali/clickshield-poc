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

**Configuration.** Compose reads `backend/.env` if it exists (Google OAuth client ID/secret, keys, …). The database, Redis, CORS and proxy settings are set in `docker-compose.yml` and override `.env`, so a `.env` written for running on the host (with `localhost` URLs) still works. Without Google credentials, set `GOOGLE_ADS_DRY_RUN=true` in `backend/.env`; otherwise protection actions fail with "Google Ads is not configured".

Useful commands:

```bash
docker compose logs -f backend worker          # follow API + worker logs
docker compose run --rm backend migrate         # run migrations only
docker compose run --rm backend alembic history # any one-off command
docker compose up db redis                      # infra only; run uvicorn / vite on the host
docker compose down                             # stop (data kept)
docker compose down -v                          # stop and DELETE the database volume
```

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
| `api` | backend, `["api"]` | 8000 | ALB target group: `GET /health` | **1 for now** (see §2.5) |
| `worker` | backend, `["worker"]` | — | container: `python -c "import os,sys,time; sys.exit(time.time()-os.path.getmtime('/tmp/clickshield-worker-heartbeat')>60)"` | 1 |
| `frontend` | frontend (default) | 80 | ALB target group: `GET /healthz` | 1–2 |

ALB rules: `/api/*` and `/health` → `api` target group; default → `frontend` target group. With path routing at the ALB, the frontend's own `/api` proxy isn't used. Set `BACKEND_UPSTREAM` to the API's internal address only if you want nginx to proxy instead.

Log configuration: `awslogs` driver for every container. The images log to stdout (`LOG_TO_FILE=false` is the image default).

### 2.3 Configuration

Secrets (Secrets Manager / SSM, injected through the task definition `secrets` block):

| Variable | Notes |
|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://USER:PASS@<rds-endpoint>:5432/clickshield` |
| `DATABASE_URL_SYNC` | `postgresql+psycopg://USER:PASS@<rds-endpoint>:5432/clickshield` (Alembic) |
| `SECRET_KEY` | JWT signing key, at least 32 random bytes |
| `TOKEN_ENCRYPTION_KEY` | Fernet key for Google refresh tokens: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth client of the Google Cloud project |
| `IPINFO_API_KEY` | optional, IP intelligence |

Plain environment variables:

| Variable | Value |
|---|---|
| `ENVIRONMENT` | `production` |
| `REDIS_URL` | `rediss://<elasticache-endpoint>:6379/0` |
| `TRUSTED_PROXY_CIDRS` | the VPC CIDR (the ALB's nodes), e.g. `10.0.0.0/16`, so client IPs come from the ALB's `X-Forwarded-For` (task 001) |
| `FRONTEND_APP_URL` | `https://app.example.com` |
| `GOOGLE_OAUTH_REDIRECT_URI` | `https://app.example.com/api/v1/google/callback` (register it in Google Cloud) |
| `API_CORS_ORIGINS` | `https://app.example.com` |
| `TRACKING_SNIPPET_BASE_URL` | public base URL that serves `/api/v1/tracking.js` |
| `RUN_MIGRATIONS` | `true` on `api` (see below); not used by `worker` |
| `UVICORN_WORKERS` | `1` (see §2.5) |

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

These come from the open tasks in the task list. Fix them before running in production:

- **Run one API task with one uvicorn worker** until **task 033**. Google OAuth `state` is held in process memory, so with more than one API process the OAuth callback can land on a process that never saw the state.
- **Task 032:** the app still has default secret values and seeds `admin@gmail.com` / a localhost website on every start. Set every secret in §2.3, and complete 032 before exposing the API.
- **Task 031:** no rate limiting yet, and `TRACKING_CORS_ORIGINS=*` (the default) currently opens CORS for the whole API.
- **Task 010:** the worker polls the action queue every `WORKER_POLL_SECONDS`. Exclusions are still *created* only when a user runs "Reconcile"/"Dry-run" in the dashboard. Automatic enqueue on a FRAUD verdict is task 010.

Infrastructure as code (Terraform / CDK) for the layout above isn't included yet.
