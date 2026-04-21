"""Terminal router — /terminal/*, /ws/terminal/*, /api/terminal/*, /api/pods/*, /api/pod-info/*."""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from kubernetes.client.rest import ApiException

from core.auth import _base_context, _get_user, _require_active_request
from core.k8s_helpers import Phase, _valid_name, _valid_ns, _valid_cluster, _token_client
from core.templates import templates
from k8s import get_api_clients, get_access_request, get_cluster_config
from terminal_ws import terminal_websocket_handler

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()


@router.get("/terminal/{cluster}/{name}", response_class=HTMLResponse)
async def terminal(request: Request, cluster: str, name: str):
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse(request, "404.html", {"path": f"/terminal/{name}"}, status_code=404)
    phase = ar.get("status", {}).get("phase", "")
    if phase != Phase.ACTIVE:
        return templates.TemplateResponse(request, "403.html", {"reason": f"Access is not active. Current phase: {phase}"}, status_code=403)
    caller, _ = _get_user(request)
    requester = ar.get("spec", {}).get("requester", "")
    if caller.lower() != requester.lower():
        return templates.TemplateResponse(request, "403.html", {"reason": "You can only access your own terminal."}, status_code=403)

    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    spec       = ar.get("spec", {})
    namespaces = spec.get("namespaces") or ([spec["namespace"]] if spec.get("namespace") else [])
    ctx = _base_context(request)
    ctx.update({
        "cluster":       cluster,
        "cluster_display": cluster_display,
        "request_name":  name,
        "namespace":     namespaces[0] if namespaces else "",
        "namespaces":    namespaces,
        "expires_at":    ar.get("status", {}).get("expiresAt", ""),
    })
    return templates.TemplateResponse(request, "terminal.html", ctx)


@router.websocket("/ws/terminal/{cluster}/{name}")
async def terminal_websocket(websocket: WebSocket, cluster: str, name: str):
    await terminal_websocket_handler(websocket, cluster, name)


@router.get("/api/pods/{cluster}/{namespace}")
async def preview_pods(cluster: str, namespace: str):
    if not _valid_cluster(cluster) or not _valid_ns(namespace):
        return JSONResponse({"error": "Invalid cluster or namespace", "pods": []}, status_code=400)
    try:
        _, core_v1 = get_api_clients(cluster)
        pods = core_v1.list_namespaced_pod(namespace=namespace)
        pod_list = [
            {
                "name":   p.metadata.name,
                "status": p.status.phase,
                "ready":  sum(1 for c in (p.status.container_statuses or []) if c.ready),
                "total":  len(p.spec.containers),
            }
            for p in pods.items
        ]
        return JSONResponse({"pods": pod_list, "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to list pods in {cluster}/{namespace}: {e}")
        return JSONResponse({"error": "Failed to list pods", "pods": []})


@router.get("/api/pod-info/{cluster}/{namespace}/{pod}", include_in_schema=False)
async def pod_info(cluster: str, namespace: str, pod: str, request: Request):
    if not _require_active_request(request, cluster, namespace):
        return JSONResponse({"error": "No active request"}, status_code=403)
    if not _valid_cluster(cluster) or not _valid_ns(namespace):
        return JSONResponse({"error": "Invalid cluster or namespace"}, status_code=400)
    try:
        _, core_v1 = get_api_clients(cluster)
        p = core_v1.read_namespaced_pod(name=pod, namespace=namespace)
    except Exception as e:
        logger.error(f"💥 pod-info {cluster}/{namespace}/{pod}: {e}")
        return JSONResponse({"error": "Pod not found"}, status_code=404)

    def _qty(q):
        return str(q) if q else None

    containers = []
    for c in (p.spec.containers or []):
        res = c.resources or {}
        req = res.requests or {}
        lim = res.limits or {}
        mounts = [
            {"name": v.name, "mountPath": v.mount_path}
            for v in (c.volume_mounts or [])
        ]
        containers.append({
            "name":       c.name,
            "image":      c.image,
            "requests":   {"cpu": _qty(req.get("cpu")), "memory": _qty(req.get("memory"))},
            "limits":     {"cpu": _qty(lim.get("cpu")), "memory": _qty(lim.get("memory"))},
            "volumeMounts": mounts,
        })

    created = p.metadata.creation_timestamp
    age_s = int((datetime.now(timezone.utc) - created).total_seconds()) if created else None

    return JSONResponse({
        "name":       p.metadata.name,
        "namespace":  p.metadata.namespace,
        "phase":      (p.status.phase or "Unknown"),
        "createdAt":  created.isoformat() if created else None,
        "ageSeconds": age_s,
        "containers": containers,
    })


@router.get("/api/terminal/{cluster}/{name}/pods")
async def list_pods(cluster: str, name: str, namespace: str = ""):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "pods": []}, status_code=400)
    core_v1, resolved_ns = _token_client(name, cluster, namespace)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "pods": []})
    try:
        pods = core_v1.list_namespaced_pod(namespace=resolved_ns)
        DISTROLESS = ("distroless", "scratch", "gcr.io/distroless", "chainguard")
        pod_list = []
        for p in pods.items:
            images    = [c.image or "" for c in p.spec.containers]
            has_shell = not any(any(d in img.lower() for d in DISTROLESS) for img in images)
            cs_list   = p.status.container_statuses or []
            restarts  = sum(cs.restart_count or 0 for cs in cs_list)
            oom       = any(
                (cs.last_state and cs.last_state.terminated and
                 cs.last_state.terminated.reason == "OOMKilled")
                for cs in cs_list
            )
            waiting_reasons = [
                cs.state.waiting.reason
                for cs in cs_list
                if cs.state and cs.state.waiting and cs.state.waiting.reason
            ]
            terminating = p.metadata.deletion_timestamp is not None
            pod_list.append({
                "name":           p.metadata.name,
                "status":         p.status.phase,
                "hasShell":       has_shell,
                "namespace":      resolved_ns,
                "restarts":       restarts,
                "oom":            oom,
                "terminating":    terminating,
                "waitingReasons": waiting_reasons,
            })
        return JSONResponse({"pods": pod_list, "namespace": resolved_ns, "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to list pods in {cluster}/{resolved_ns}: {e}")
        return JSONResponse({"error": "Failed to list pods", "pods": []})


@router.get("/api/terminal/{cluster}/{name}/{pod}/logs")
async def get_pod_logs(cluster: str, name: str, pod: str, namespace: str = "", tail: int = 500):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "logs": ""}, status_code=400)
    tail = max(10, min(tail, 5000))
    core_v1, resolved_ns = _token_client(name, cluster, namespace)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "logs": ""})
    try:
        logs = core_v1.read_namespaced_pod_log(name=pod, namespace=resolved_ns, tail_lines=tail, timestamps=True)
        return JSONResponse({"logs": logs or "", "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to get logs for {cluster}/{resolved_ns}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod logs", "logs": ""})


@router.get("/api/terminal/{cluster}/{name}/{pod}/events")
async def get_pod_events(cluster: str, name: str, pod: str, namespace: str = ""):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "events": []}, status_code=400)
    core_v1, resolved_ns = _token_client(name, cluster, namespace)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "events": []})
    try:
        events = core_v1.list_namespaced_event(
            namespace=resolved_ns, field_selector=f"involvedObject.name={pod}"
        )
        event_list = [
            {
                "type":           e.type,
                "reason":         e.reason,
                "message":        e.message,
                "count":          e.count,
                "firstTimestamp": e.first_timestamp.isoformat() if e.first_timestamp else "",
                "lastTimestamp":  e.last_timestamp.isoformat()  if e.last_timestamp  else "",
            }
            for e in events.items
        ]
        event_list.sort(key=lambda x: x["lastTimestamp"], reverse=True)
        return JSONResponse({"events": event_list, "error": None})
    except ApiException as e:
        if e.status == 403:
            logger.warning(f"⛔ Events forbidden for {cluster}/{resolved_ns}/{pod}")
            return JSONResponse({"events": [], "forbidden": True, "error": None})
        logger.error(f"💥 Failed to get events for {cluster}/{resolved_ns}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod events", "events": []})
    except Exception as e:
        logger.error(f"💥 Failed to get events for {cluster}/{resolved_ns}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod events", "events": []})
