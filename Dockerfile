FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY flightrecorder ./flightrecorder

RUN pip install --no-cache-dir .[billing]

# DB durability: FlightRecorder stores its ledger/anchors/keys/plans as
# JSON/JSONL files (no sqlite3 or SQLAlchemy in this repo), so durability is
# provided by mounting a persistent volume at FLIGHTRECORDER_DATA_DIR --
# do that in production, not the container layer.
ENV FLIGHTRECORDER_DATA_DIR=/app/data
VOLUME ["/app/data"]

EXPOSE 8015

# Honor Cloud Run's PORT env var (falls back to 8015 for local `docker run`).
CMD ["sh", "-c", "uvicorn flightrecorder.app:app --host 0.0.0.0 --port ${PORT:-8015}"]
