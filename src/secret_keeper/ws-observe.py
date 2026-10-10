import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import ctx


def write(record):
    if not ctx.options.ws_trace_file:
        return

    record["time"] = datetime.now(timezone.utc).isoformat()
    path = Path(ctx.options.ws_trace_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as out:
        out.write(json.dumps(record, ensure_ascii=True) + "\n")


def load(loader):
    loader.add_option(
        "ws_trace_file", str, "",
        "Sensitive diagnostic WebSocket trace; disabled when empty",
    )


def websocket_start(flow):
    write({
        "event": "ws_start",
        "flow_id": flow.id,
        "client_connection_id": flow.client_conn.id,
        "host": flow.request.host,
        "path": flow.request.path.split("?", 1)[0],
        "offered_protocol": flow.request.headers.get(
            "Sec-WebSocket-Protocol", ""
        ),
        "selected_protocol": flow.response.headers.get(
            "Sec-WebSocket-Protocol", ""
        ),
    })


def websocket_message(flow):
    msg = flow.websocket.messages[-1]
    limit = 262144
    raw = msg.content[:limit]

    record = {
        "event": "ws_message",
        "flow_id": flow.id,
        "client_connection_id": flow.client_conn.id,
        "index": len(flow.websocket.messages) - 1,
        "direction": "client_to_server" if msg.from_client
                     else "server_to_client",
        "injected": msg.injected,
        "dropped": msg.dropped,
        "is_text": msg.is_text,
        "bytes": len(msg.content),
        "truncated": len(msg.content) > limit,
    }

    if msg.is_text:
        text = raw.decode("utf-8", errors="replace")
        record["text"] = text
        if not record["truncated"]:
            try:
                record["json"] = json.loads(text)
            except (ValueError, RecursionError):
                pass
    else:
        record["base64"] = base64.b64encode(raw).decode("ascii")

    write(record)


def websocket_end(flow):
    write({
        "event": "ws_end",
        "flow_id": flow.id,
        "client_connection_id": flow.client_conn.id,
        "close_code": flow.websocket.close_code,
        "close_reason": flow.websocket.close_reason,
        "closed_by_client": flow.websocket.closed_by_client,
    })


def client_disconnected(client):
    write({
        "event": "client_disconnected",
        "client_connection_id": client.id,
    })