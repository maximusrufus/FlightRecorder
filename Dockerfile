FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY flightrecorder ./flightrecorder

RUN pip install --no-cache-dir .[billing]

ENV FLIGHTRECORDER_DATA_DIR=/app/data
VOLUME ["/app/data"]

EXPOSE 8015

CMD ["uvicorn", "flightrecorder.app:app", "--host", "0.0.0.0", "--port", "8015"]
