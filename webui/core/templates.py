"""
Shared Jinja2Templates instance.
"""

import os
from fastapi.templating import Jinja2Templates

APP_DIR = os.environ.get("APP_DIR", os.path.join(os.path.dirname(__file__), ".."))
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))
