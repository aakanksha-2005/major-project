"""FastAPI application factory.

`python -m uvicorn rasp.main:app` starts the prototype. Startup validates
the policy configuration and refuses to serve on invalid/contradictory
security settings (fail closed).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from rasp import __version__
from rasp.api import (
    BodySizeLimitMiddleware,
    register_exception_handlers,
    register_routes,
)
from rasp.container import build_container
from rasp.settings import Settings, load_settings

logger = logging.getLogger("rasp")

DESCRIPTION = """\
**RASP — Runtime Agent Safety Platform**

Experimental prototype — not production-certified.

The model (mock in Milestone 1) proposes actions; RASP independently
authorizes and mediates every tool call. Model output is never an
authorization decision.

Authentication (development mechanism): send `X-Dev-Principal` and
`X-Dev-Permissions` headers, e.g. `documents:read,system:status`.
This is NOT production authentication.
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    container = build_container(settings)  # raises on invalid policy

    app = FastAPI(
        title="RASP — Runtime Agent Safety Platform",
        version=__version__,
        description=DESCRIPTION,
    )
    app.state.container = container
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    register_exception_handlers(app)
    register_routes(app)

    logger.info(
        "RASP started: policy_version=%s provider=%s prototype=true",
        container.policy_config.version,
        container.model.model_id,
    )
    return app


app = create_app()
