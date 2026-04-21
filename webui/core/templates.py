"""
Shared Jinja2Templates instance.
"""

import os
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from core.k8s_helpers import _to_berlin

APP_DIR = os.environ.get("APP_DIR", os.path.join(os.path.dirname(__file__), ".."))
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))
templates.env.filters["to_berlin"] = _to_berlin


def _csp_nonce(request: Request) -> str:
    return getattr(request.state, "csp_nonce", "")


templates.env.globals["csp_nonce"] = _csp_nonce
