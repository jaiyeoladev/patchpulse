# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATABASE_PATH=/data/patchpulse.db

WORKDIR /app
RUN useradd --create-home --uid 10001 app && mkdir -p /data && chown app:app /data

COPY pyproject.toml README.md LICENSE ./
COPY patchpulse ./patchpulse
RUN pip install .

USER app
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

# One worker: scans run in-process and SQLite is the store.
CMD ["uvicorn", "patchpulse.app:build", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
