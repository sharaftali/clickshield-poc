# Click Shield backend image — one image, several roles (see docker/entrypoint.sh):
#   api (default) | worker | migrate
# Used by docker-compose locally and by ECS on AWS.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOG_TO_FILE=false

# libpq: runtime library for psycopg (used by Alembic's sync connection)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# sed: strip CRLF in case the file was checked out on Windows without .gitattributes
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh \
    && useradd --system --uid 10001 --home-dir /app clickshield \
    && chown -R clickshield /app

USER clickshield

EXPOSE 8000

# No HEALTHCHECK here: the same image runs the API and the worker, which are
# checked differently (see docker-compose.yml / the ECS task definitions).
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["api"]
