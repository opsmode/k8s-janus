"""Audit router — /api/audit/*, /logs, /api/system-logs/*."""
import asyncio
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from core.auth import _require_admin
from core.k8s_helpers import _valid_name
from core.templates import templates
from db import get_recent_audit_logs, get_audit_log
from k8s import JANUS_NAMESPACE

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()


@router.get("/api/audit")
async def audit_recent(limit: int = 200, offset: int = 0):
    return JSONResponse(get_recent_audit_logs(limit=min(limit, 500), offset=offset))


@router.get("/api/audit/{name}")
async def audit_for_request(name: str):
    if not _valid_name(name):
        return JSONResponse({"error": "Invalid request name"}, status_code=400)
    return JSONResponse(get_audit_log(name))


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    if (err := _require_admin(request)):
        return err
    from core.auth import _base_context
    ctx = _base_context(request)
    return templates.TemplateResponse(request, "logs.html", ctx)


@router.get("/api/system-logs/{component}")
async def stream_system_logs(request: Request, component: str, tail: int = 200):
    if (err := _require_admin(request)):
        return err
    if component not in ("controller", "webui"):
        return JSONResponse({"error": "component must be 'controller' or 'webui'"}, status_code=400)
    tail = max(10, min(tail, 5000))

    from k8s import _get_central_core_v1
    try:
        core_v1 = _get_central_core_v1()
        pods = core_v1.list_namespaced_pod(
            namespace=JANUS_NAMESPACE,
            label_selector=f"app.kubernetes.io/name=janus-{component}",
        )
        if not pods.items:
            async def _no_pod():
                yield f"data: [no {component} pod found in {JANUS_NAMESPACE}]\n\n"
            return StreamingResponse(_no_pod(), media_type="text/event-stream")
        pod_name = pods.items[0].metadata.name
    except Exception as e:
        async def _err_gen(msg=str(e)):
            yield f"data: [error resolving pod: {msg}]\n\n"
        return StreamingResponse(_err_gen(), media_type="text/event-stream")

    async def _log_generator():
        loop = asyncio.get_event_loop()

        def _fetch_tail():
            try:
                return core_v1.read_namespaced_pod_log(
                    name=pod_name, namespace=JANUS_NAMESPACE,
                    tail_lines=tail, timestamps=False,
                )
            except Exception as exc:
                return f"[error: {exc}]"

        lines = await loop.run_in_executor(None, _fetch_tail)
        for line in (lines or "").splitlines():
            yield f"data: {line}\n\n"

        def _stream_follow():
            try:
                return core_v1.read_namespaced_pod_log(
                    name=pod_name, namespace=JANUS_NAMESPACE,
                    follow=True, _preload_content=False,
                )
            except Exception:
                return None

        resp = await loop.run_in_executor(None, _stream_follow)
        if resp is None:
            yield "data: [could not open log stream]\n\n"
            return

        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        def _safe_put(item):
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                pass

        def _reader():
            try:
                for chunk in resp:
                    text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, (bytes, bytearray)) else str(chunk)
                    for line in text.splitlines():
                        if line and "fsnotify" not in line:
                            loop.call_soon_threadsafe(_safe_put, line)
            except Exception as exc:
                loop.call_soon_threadsafe(_safe_put, f"[stream ended: {exc}]")
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
                loop.call_soon_threadsafe(_safe_put, None)

        loop.run_in_executor(None, _reader)
        while True:
            item = await queue.get()
            if item is None:
                break
            yield f"data: {item}\n\n"

    return StreamingResponse(_log_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
