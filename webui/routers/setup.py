"""Setup wizard router — /setup/*, /ws/setup/*, /api/setup/*, /api/clusters."""
import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, Request, UploadFile, File, WebSocket
from fastapi.responses import JSONResponse

from core.auth import _base_context, _require_admin
from core.templates import templates
from k8s import JANUS_NAMESPACE, invalidate_clusters_cache

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()

# In-memory setup session state (single-process; not shared across replicas)
_setup_kubeconfigs: dict[str, dict] = {}
_setup_queues: dict[str, asyncio.Queue] = {}


@router.get("/setup", response_class=None)
async def setup_page(request: Request):
    return templates.TemplateResponse(request, "setup.html", _base_context(request))


@router.get("/setup/upload-helper")
async def setup_upload_helper():
    from fastapi.responses import FileResponse
    _APP_DIR = os.environ.get("APP_DIR", "/app")
    script_path = os.path.join(_APP_DIR, "setup-upload.sh")
    if not os.path.isfile(script_path):
        return JSONResponse({"error": "Helper script not found."}, status_code=404)
    return FileResponse(
        script_path,
        media_type="text/x-shellscript",
        filename="setup-upload.sh",
        headers={"Content-Disposition": "attachment; filename=setup-upload.sh"},
    )


@router.post("/setup/upload")
async def setup_upload(kubeconfig: UploadFile = File(...)):
    raw = await kubeconfig.read()
    if len(raw) > 1024 * 1024:
        return JSONResponse({"error": "File too large (max 1 MB)."}, status_code=400)
    try:
        from setup import parse_kubeconfig, list_contexts
        kc = parse_kubeconfig(raw)
        contexts = list_contexts(kc)
    except ValueError as e:
        return JSONResponse({"error": str(e)})
    session_id = str(uuid.uuid4())
    _setup_kubeconfigs[session_id] = kc
    return JSONResponse({"session_id": session_id, "contexts": contexts, "error": None})


@router.get("/setup/contexts/{session_id}")
async def setup_contexts(session_id: str):
    if session_id not in _setup_kubeconfigs:
        return JSONResponse({"error": "Session not found or expired."}, status_code=404)
    from setup import list_contexts
    contexts = list_contexts(_setup_kubeconfigs[session_id])
    return JSONResponse({"session_id": session_id, "contexts": contexts, "error": None})


@router.post("/setup/run")
async def setup_run(request: Request):
    body = await request.json()
    session_id      = body.get("session_id", "")
    central         = body.get("central", "")
    central_name    = body.get("central_name", "")
    central_display = body.get("central_display", "")
    remotes         = body.get("remotes", [])

    if not session_id or session_id not in _setup_kubeconfigs:
        return JSONResponse({"error": "Session not found. Please re-upload your kubeconfig."}, status_code=400)

    kc = _setup_kubeconfigs[session_id]
    q: asyncio.Queue = asyncio.Queue()
    _setup_queues[session_id] = q
    central = central or central_name or "cluster1"
    display = central_display or central_name or central
    asyncio.ensure_future(_run_setup_task(session_id, kc, central, display, remotes, JANUS_NAMESPACE, q))
    return JSONResponse({"ok": True})


@router.get("/api/clusters")
async def api_clusters():
    from k8s import get_clusters
    return JSONResponse(get_clusters())


@router.post("/setup/rename-cluster")
async def setup_rename_cluster(request: Request):
    body         = await request.json()
    cluster_name = body.get("cluster_name", "").strip()
    display_name = body.get("display_name", "").strip()
    if not cluster_name or not display_name:
        return JSONResponse({"error": "cluster_name and display_name are required."}, status_code=400)

    from kubernetes import client as k8s_client, config as k8s_config
    from k8s import _CENTRAL_NAME
    is_central  = (cluster_name == _CENTRAL_NAME)
    secret_name = "janus-central-display" if is_central else f"{cluster_name}-kubeconfig"

    try:
        k8s_config.load_incluster_config()
        core = k8s_client.CoreV1Api()
        if is_central:
            secret_body = k8s_client.V1Secret(
                metadata=k8s_client.V1ObjectMeta(
                    name=secret_name,
                    namespace=JANUS_NAMESPACE,
                    labels={"k8s-janus.infroware.com/managed": "true"},
                    annotations={"k8s-janus.infroware.com/displayName": display_name},
                ),
                type="Opaque",
            )
            try:
                core.create_namespaced_secret(namespace=JANUS_NAMESPACE, body=secret_body)
            except k8s_client.exceptions.ApiException as e:
                if e.status == 409:
                    core.patch_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE, body=secret_body)
                else:
                    raise
        else:
            core.patch_namespaced_secret(
                name=secret_name,
                namespace=JANUS_NAMESPACE,
                body={"metadata": {"annotations": {"k8s-janus.infroware.com/displayName": display_name}}},
            )
        invalidate_clusters_cache()
        return JSONResponse({"ok": True})
    except Exception as e:
        logger.error(f"Failed to rename cluster {cluster_name!r}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.post("/setup/remove-cluster")
async def setup_remove_cluster(request: Request):
    body         = await request.json()
    cluster_name = body.get("cluster_name", "").strip()
    session_id   = body.get("session_id", "")
    context_name = body.get("context", "")

    if not cluster_name:
        return JSONResponse({"error": "cluster_name is required."}, status_code=400)

    loop = asyncio.get_event_loop()
    kubeconfig = _setup_kubeconfigs.get(session_id) if session_id else None

    from setup import remove_cluster, _rollout_restart_deployments
    lines = await loop.run_in_executor(
        None, remove_cluster, cluster_name, JANUS_NAMESPACE,
        kubeconfig, context_name or None
    )
    invalidate_clusters_cache()

    had_error = any(line.startswith("[ERROR]") for line in lines)
    if not had_error:
        try:
            await loop.run_in_executor(None, _rollout_restart_deployments, JANUS_NAMESPACE)
            lines.append("[INFO] Restarting pods to apply changes...")
        except Exception as e:
            lines.append(f"[WARN]  Pod restart failed (non-fatal): {e}")

    return JSONResponse({"lines": lines, "ok": not had_error})


@router.post("/api/setup/restart-deployments")
async def setup_restart_deployments():
    from setup import _rollout_restart_deployments
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _rollout_restart_deployments, JANUS_NAMESPACE)
        return JSONResponse({"ok": True, "message": "Deployments restarted."})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@router.get("/api/setup/redirect-url")
async def setup_redirect_url(request: Request):
    base_url = os.environ.get("WEBUI_BASE_URL", "").rstrip("/")
    if not base_url:
        try:
            from k8s import _get_central_core_v1
            from kubernetes import client as _k8s_client
            core_v1 = _get_central_core_v1()

            try:
                net_v1 = _k8s_client.NetworkingV1Api(core_v1.api_client)
                for ing in net_v1.list_namespaced_ingress(namespace=JANUS_NAMESPACE).items:
                    for rule in (ing.spec.rules or []):
                        if rule.host:
                            tls_hosts = [h for tls in (ing.spec.tls or []) for h in (tls.hosts or [])]
                            scheme = "https" if rule.host in tls_hosts else "http"
                            base_url = f"{scheme}://{rule.host}"
                            break
                    if base_url:
                        break
            except Exception:
                pass

            if not base_url:
                for svc in core_v1.list_namespaced_service(namespace=JANUS_NAMESPACE).items:
                    if svc.spec.type != "LoadBalancer":
                        continue
                    ingresses = (svc.status.load_balancer.ingress or []) if svc.status.load_balancer else []
                    if ingresses:
                        lb = ingresses[0]
                        host = lb.hostname or lb.ip
                        if host:
                            base_url = f"http://{host}"
                            break
        except Exception:
            pass
    if not base_url:
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host   = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
        base_url = f"{scheme}://{host}"
    return JSONResponse({"url": f"{base_url}/"})


@router.websocket("/ws/setup/{session_id}")
async def setup_websocket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    q = _setup_queues.get(session_id)
    if q is None:
        await websocket.send_json({"type": "error", "text": "Session not found."})
        await websocket.close()
        return
    try:
        while True:
            msg = await q.get()
            if msg is None:
                await websocket.send_json({"type": "done"})
                break
            await websocket.send_json({"type": "line", "text": msg})
    except Exception:
        pass
    finally:
        _setup_queues.pop(session_id, None)
        try:
            await websocket.close()
        except Exception:
            pass


async def _run_setup_task(
    session_id: str,
    kubeconfig: dict,
    central: str,
    central_name: str,
    remotes: list,
    janus_namespace: str,
    q: asyncio.Queue,
) -> None:
    try:
        from setup import run_setup
        async for line in run_setup(kubeconfig, central, central_name, remotes, janus_namespace):
            await q.put(line)
        invalidate_clusters_cache()
    except Exception as e:
        await q.put(f"[FATAL] Unexpected error: {e}")
    finally:
        _setup_kubeconfigs.pop(session_id, None)
        await q.put(None)
