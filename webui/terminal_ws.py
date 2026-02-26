"""
WebSocket terminal handler for K8s-Janus.

Features:
- Persistent WS per session; switch pods via select_pod message
- Dedicated stream thread per pod (thread-safe I/O via queues)
- Command capture for audit trail
- Idle timeout with warning banner
- Broadcast message reception
"""

import os
import json
import time
import asyncio
import logging
import threading
import queue as _queue

from fastapi import WebSocket, WebSocketDisconnect
from kubernetes.stream import stream

from k8s import get_api_clients, get_client_with_token, read_token_secret, CLUSTERS, JANUS_NAMESPACE
from db import log_command

logger = logging.getLogger("k8s-janus-webui")

IDLE_TIMEOUT_SECONDS = int(os.environ.get("IDLE_TIMEOUT_SECONDS", "900"))
IDLE_WARNING_SECONDS = 120

# ---------------------------------------------------------------------------
# Global broadcast registry:  request_name → set of WebSocket objects
# ---------------------------------------------------------------------------
_active_sessions: dict[str, set] = {}
_sessions_lock = asyncio.Lock()
_MAX_WS_PER_USER = 4
_WS_MAX_MSG_BYTES = 4096  # max keystroke payload size


async def _register_ws(name: str, ws: WebSocket) -> bool:
    """Register a WebSocket. Returns False if per-user cap exceeded."""
    async with _sessions_lock:
        existing = _active_sessions.get(name, set())
        if len(existing) >= _MAX_WS_PER_USER:
            return False
        _active_sessions.setdefault(name, set()).add(ws)
    return True


async def _unregister_ws(name: str, ws: WebSocket):
    async with _sessions_lock:
        s = _active_sessions.get(name, set())
        s.discard(ws)


async def broadcast_to_all(message: str, sender: str) -> int:
    """Send a broadcast message to every active terminal session. Returns recipient count."""
    payload = json.dumps({"type": "broadcast", "message": message, "from": sender})
    count = 0
    async with _sessions_lock:
        all_ws = [ws for sessions in _active_sessions.values() for ws in sessions]
    failed = 0
    for ws in all_ws:
        try:
            await ws.send_text(payload)
            count += 1
        except Exception as e:
            failed += 1
            logger.debug(f"📭 Broadcast failed for one session: {e}")
    if failed:
        logger.warning(f"📣 Broadcast: {count} sent, {failed} failed")
    return count


async def notify_revoked(name: str, revoked_by: str) -> int:
    """Send a revoked signal to all WebSocket sessions for a specific request."""
    payload = json.dumps({"type": "revoked", "revoked_by": revoked_by})
    async with _sessions_lock:
        sessions = list(_active_sessions.get(name, set()))
    count = 0
    for ws in sessions:
        try:
            await ws.send_text(payload)
            count += 1
        except Exception as e:
            logger.debug(f"📭 Revoke notify failed for session: {e}")
    if count:
        logger.info(f"🔒 Revoke signal sent to {count} terminal session(s) for {name}")
    return count


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def _open_shell(core_v1, pod: str, namespace: str):
    """Probe then open an interactive TTY shell. Returns (stream, shell_path) or (None, None)."""
    for shell in ('/bin/bash', '/bin/sh', '/bin/ash'):
        try:
            probe = stream(
                core_v1.connect_get_namespaced_pod_exec,
                pod, namespace,
                command=[shell, '-c', 'echo ok'],
                stderr=True, stdin=False, stdout=True, tty=False,
                _preload_content=True,
            )
            if 'ok' not in (probe or ''):
                logger.info(f"🔍 Terminal: {shell} probe failed on {pod}")
                continue
            s = stream(
                core_v1.connect_get_namespaced_pod_exec,
                pod, namespace,
                command=[shell],
                stderr=True, stdin=True, stdout=True, tty=True,
                _preload_content=False,
            )
            time.sleep(0.3)
            if s.is_open():
                logger.info(f"🖥️  Terminal: opened {shell} on {pod}")
                return s, shell
            s.close()
        except Exception as e:
            logger.info(f"⚠️  Terminal: {shell} on {pod} failed: {e}")
    return None, None


def _stream_thread(exec_resp, pod_name: str,
                   stdin_q: _queue.Queue, out_q: _queue.Queue,
                   stop_evt: threading.Event,
                   request_name: str):
    """Single thread owns all stream I/O + command capture."""
    cmd_buf: list[str] = []
    try:
        while not stop_evt.is_set() and exec_resp.is_open():
            # Drain keystrokes
            while True:
                try:
                    data = stdin_q.get_nowait()
                    exec_resp.write_stdin(data)
                    # Command capture — reconstruct lines from raw keystrokes
                    for ch in data:
                        if ch in ('\r', '\n'):
                            line = ''.join(cmd_buf).strip()
                            if line:
                                log_command(request_name, pod_name, line)
                            cmd_buf.clear()
                        elif ch == '\x7f':          # backspace
                            if cmd_buf:
                                cmd_buf.pop()
                        elif ch == '\x03':          # Ctrl-C
                            cmd_buf.clear()
                        elif not ch.startswith('\x1b') and ch.isprintable():
                            cmd_buf.append(ch)
                except _queue.Empty:
                    break

            exec_resp.update(timeout=0.1)
            if exec_resp.peek_stdout():
                out_q.put(exec_resp.read_stdout())
            if exec_resp.peek_stderr():
                out_q.put(exec_resp.read_stderr())
    except Exception as e:
        logger.debug(f"🧵 Stream thread ended for {pod_name}: {e}")
    finally:
        out_q.put(None)


async def _read_pod(loop, websocket: WebSocket, out_q: _queue.Queue, pod_name: str):
    """Forward chunks from out_q to websocket."""
    try:
        while True:
            chunk = await loop.run_in_executor(None, out_q.get)
            if chunk is None:
                break
            await websocket.send_text(chunk)
    except Exception as e:
        logger.debug(f"📭 Read task ended for {pod_name}: {e}")


# ---------------------------------------------------------------------------
# Main WebSocket handler
# ---------------------------------------------------------------------------

async def terminal_websocket_handler(websocket: WebSocket, cluster: str, name: str):
    await websocket.accept()
    if not await _register_ws(name, websocket):
        await websocket.send_text("Error: Too many concurrent sessions for this request\r\n")
        await websocket.close()
        return

    from k8s import get_access_request
    ar = get_access_request(name, cluster)
    if not ar or ar.get("status", {}).get("phase") != "Active":
        await websocket.send_text("Error: Access not active\r\n")
        await websocket.close()
        await _unregister_ws(name, websocket)
        return

    namespace   = ar.get("spec", {}).get("namespace", "")
    ar_status   = ar.get("status", {})
    secret_name = ar_status.get("tokenSecret", "")
    expires_at  = ar_status.get("expiresAt", "")

    if not namespace or not secret_name:
        await websocket.send_text("Error: Missing namespace or token\r\n")
        await websocket.close()
        await _unregister_ws(name, websocket)
        return

    try:
        token, server, ca = read_token_secret(secret_name)
        core_v1 = get_client_with_token(cluster, token, server, ca)
    except Exception as e:
        logger.error(f"💥 Terminal setup error: {e}")
        await websocket.send_text(f"\r\nError: {e}\r\n")
        await websocket.close()
        await _unregister_ws(name, websocket)
        return

    loop = asyncio.get_event_loop()

    resp      = None
    read_task = None
    stop_evt: threading.Event | None  = None
    stdin_q: _queue.Queue             = _queue.Queue()
    last_activity                     = time.monotonic()
    idle_warned                       = False

    async def _idle_checker():
        nonlocal last_activity, idle_warned
        while True:
            await asyncio.sleep(10)
            idle = time.monotonic() - last_activity
            remaining = int(IDLE_TIMEOUT_SECONDS - idle)
            if remaining <= 0:
                await websocket.send_text(json.dumps({"type": "idle_timeout"}))
                # Auto-revoke the AccessRequest — awaited directly so errors surface
                try:
                    await _auto_revoke(name, cluster)
                except Exception as e:
                    logger.error(f"💥 _auto_revoke failed for {name}: {e}")
                return
            elif remaining <= IDLE_WARNING_SECONDS and not idle_warned:
                idle_warned = True
                await websocket.send_text(json.dumps({"type": "idle_warning", "seconds_left": remaining}))

    idle_task = asyncio.ensure_future(_idle_checker())

    try:
        while True:
            data = await websocket.receive_text()

            # Reject oversized frames before any processing
            if len(data.encode("utf-8", errors="replace")) > _WS_MAX_MSG_BYTES:
                logger.warning(f"⚠️  Oversized WS frame ({len(data)} chars) dropped for {name}")
                continue

            try:
                msg = json.loads(data)
                if not isinstance(msg, dict):
                    raise ValueError("not a dict")
            except (json.JSONDecodeError, ValueError):
                # Plain keystroke
                if resp and resp.is_open():
                    stdin_q.put(data)
                last_activity = time.monotonic()
                idle_warned = False
                continue

            msg_type = msg.get("type")

            if msg_type == "activity":
                last_activity = time.monotonic()
                idle_warned = False

            elif msg_type == "select_pod":
                pod = msg.get("pod", "")
                if not pod:
                    continue

                last_activity = time.monotonic()
                idle_warned = False

                # Stop previous stream
                if stop_evt:
                    stop_evt.set()
                if read_task and not read_task.done():
                    read_task.cancel()
                    try:
                        await read_task
                    except asyncio.CancelledError:
                        pass
                if resp:
                    try:
                        resp.close()
                    except Exception:
                        pass
                    resp = None
                while not stdin_q.empty():
                    try:
                        stdin_q.get_nowait()
                    except _queue.Empty:
                        break

                await websocket.send_text(f"\r\n\x1b[33mConnecting to {pod}…\x1b[0m\r\n")
                new_resp, used_shell = await loop.run_in_executor(
                    None, _open_shell, core_v1, pod, namespace
                )

                if new_resp is None:
                    await websocket.send_text(
                        f"\r\n\x1b[31m✗ No shell found in {pod}.\x1b[0m\r\n"
                        "Tried: /bin/bash, /bin/sh, /bin/ash\r\n"
                        "Pod may be distroless — use Logs tab instead.\r\n"
                    )
                    await websocket.send_text(json.dumps({"type": "no_shell", "pod": pod}))
                    continue

                resp = new_resp
                stop_evt = threading.Event()
                out_q: _queue.Queue = _queue.Queue()
                threading.Thread(
                    target=_stream_thread,
                    args=(resp, pod, stdin_q, out_q, stop_evt, name),
                    daemon=True,
                ).start()
                read_task = asyncio.ensure_future(_read_pod(loop, websocket, out_q, pod))
                await websocket.send_text(f"\r\n\x1b[32mConnected to {pod} ({used_shell})\x1b[0m\r\n\r\n")
                await websocket.send_text(json.dumps({"type": "connected", "pod": pod}))

            elif msg_type == "resize":
                pass  # informational only with sync k8s client

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"💥 Terminal session error: {e}")
        try:
            await websocket.send_text(f"\r\nSession error: {e}\r\n")
        except Exception:
            pass
    finally:
        idle_task.cancel()
        if stop_evt:
            stop_evt.set()
        if read_task and not read_task.done():
            read_task.cancel()
        if resp:
            try:
                resp.close()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass
        await _unregister_ws(name, websocket)


async def _auto_revoke(name: str, cluster: str):
    """Patch the AccessRequest to Revoked due to idle timeout."""
    from datetime import datetime, timezone
    from kubernetes.client.rest import ApiException
    try:
        from k8s import get_api_clients, CLUSTERS, CRD_GROUP
        custom_api, _ = get_api_clients(CLUSTERS[0]["name"])
        custom_api.patch_cluster_custom_object_status(
            group=CRD_GROUP, version="v1alpha1", plural="accessrequests", name=name,
            body={"status": {
                "phase": "Revoked",
                "message": "Auto-revoked due to idle timeout",
                "approvedBy": "system",
                "approvedAt": datetime.now(timezone.utc).isoformat(),
            }},
        )
        from db import log_audit
        log_audit(name, "access.idle_revoked", actor="system",
                  detail=f"idle>{IDLE_TIMEOUT_SECONDS}s")
        logger.info(f"🔒 Auto-revoked {name} due to idle timeout")
    except Exception as e:
        logger.error(f"💥 Failed to auto-revoke {name}: {e}")
