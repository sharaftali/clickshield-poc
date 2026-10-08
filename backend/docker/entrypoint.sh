#!/bin/sh
# Container entrypoint for the Click Shield backend image.
#
#   api      run database migrations (unless RUN_MIGRATIONS=false), then serve the API
#   worker   run the protection-action worker (no migrations, no HTTP)
#   migrate  run database migrations and exit (one-off task, e.g. before an ECS deploy)
#   *        run any other command, e.g. `docker compose run backend alembic history`
set -eu

migrate() {
    attempt=1
    max_attempts="${MIGRATION_MAX_ATTEMPTS:-10}"
    # The database may still be starting (compose) or briefly unreachable (RDS failover).
    until alembic upgrade head; do
        if [ "$attempt" -ge "$max_attempts" ]; then
            echo "entrypoint: migrations failed after $attempt attempts" >&2
            exit 1
        fi
        echo "entrypoint: migration attempt $attempt failed, retrying in 3s" >&2
        attempt=$((attempt + 1))
        sleep 3
    done
}

role="${1:-api}"

case "$role" in
    api)
        if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
            echo "entrypoint: running database migrations"
            migrate
        fi
        # --no-proxy-headers: client IPs are resolved by app/core/client_ip.py using
        # TRUSTED_PROXY_CIDRS; uvicorn must not rewrite them first (task 001).
        # Keep UVICORN_WORKERS=1 until OAuth state moves to Redis (task 033).
        exec uvicorn app.main:app \
            --host 0.0.0.0 \
            --port "${PORT:-8000}" \
            --workers "${UVICORN_WORKERS:-1}" \
            --no-proxy-headers
        ;;
    worker)
        # arq: process_action jobs pushed by the API + a periodic sweep (retries, overflow, expiry)
        exec arq app.workers.arq_worker.WorkerSettings
        ;;
    migrate)
        migrate
        ;;
    *)
        exec "$@"
        ;;
esac
