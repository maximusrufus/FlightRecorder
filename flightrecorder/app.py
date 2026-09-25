"""Top-level hosted-service ASGI app: mounts the ingest/export/verify API
(`flightrecorder.proxy.app`), marketing pages (`flightrecorder.web`), and
billing (`flightrecorder.billing`) onto one FastAPI application.

Run with: `uvicorn flightrecorder.app:app --port 8015`
"""

from __future__ import annotations

from . import billing, web
from .proxy import app as api_app

app = api_app
app.include_router(web.router)
app.include_router(billing.router)
