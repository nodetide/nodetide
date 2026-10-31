"""Pairing slots: a new device of an identity and an existing device of it meet through the node.

The new device opens a slot named by the hash of a secret code it shows its owner and publishes its PUBLIC keys; the owner
types the code into the existing wallet, which authorizes the device on the sigchain and leaves a response sealed to the
new device's key. The node only relays those two small messages for a few minutes and can read neither the code nor the
sealed response. Slots live in memory.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from aiohttp import web

from nodetide.api.claims import error, read_object

SLOT_TTL = 600
MAX_SLOTS = 200
MAX_LABEL = 64
MAX_SEALED = 2 * 1024 * 1024  # characters of base64


@dataclass
class Slot:
    request: dict[str, str]
    expires_at: int
    response: dict[str, str] | None = None


def is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def slots(request: web.Request) -> dict[str, Slot]:
    store: dict[str, Slot] = request.app["pairing_slots"]
    now = time.time()
    for key in [k for k, v in store.items() if v.expires_at < now]:
        del store[key]
    return store


def slot_or_error(request: web.Request) -> tuple[Slot | None, web.Response | None]:
    name = request.match_info["slot"]
    slot = slots(request).get(name) if is_hex(name, 64) else None
    if slot is None:
        return None, error("not_found", "No such pairing, or it has expired", 404)
    return slot, None


async def open_slot(request: web.Request) -> web.Response:
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    name, req = data.get("slot"), data.get("request")
    if not is_hex(name, 64) or not isinstance(req, dict):
        return error("invalid_request", "slot (64 hex) and request are required", 400)
    label = req.get("label")
    if not (is_hex(req.get("device_pubkey"), 64) and is_hex(req.get("device_encryption_pubkey"), 64)
            and isinstance(label, str) and 0 < len(label) <= MAX_LABEL):
        return error("invalid_request", "request needs device_pubkey, device_encryption_pubkey (64 hex each) and a short label", 400)
    store = slots(request)
    if name in store:
        return error("conflict", "This pairing is already open", 409)
    if len(store) >= MAX_SLOTS:
        return error("busy", "Too many pairings are open; try again in a few minutes", 503)
    expires_at = int(time.time()) + SLOT_TTL
    store[name] = Slot({k: req[k] for k in ("device_pubkey", "device_encryption_pubkey", "label")}, expires_at)
    return web.json_response({"expires_at": expires_at}, status=201)


async def get_slot(request: web.Request) -> web.Response:
    slot, problem = slot_or_error(request)
    if problem:
        return problem
    return web.json_response({"request": slot.request, "response": slot.response, "expires_at": slot.expires_at})


async def put_response(request: web.Request) -> web.Response:
    slot, problem = slot_or_error(request)
    if problem:
        return problem
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    response = data.get("response")
    if (not isinstance(response, dict) or not is_hex(response.get("from_encryption_pubkey"), 64)
            or not isinstance(response.get("sealed"), str) or not 0 < len(response["sealed"]) <= MAX_SEALED):
        return error("invalid_request", "response needs from_encryption_pubkey (64 hex) and sealed", 400)
    if slot.response is not None:
        return error("conflict", "This pairing already has a response", 409)
    slot.response = {"from_encryption_pubkey": response["from_encryption_pubkey"], "sealed": response["sealed"]}
    return web.json_response({"ok": True}, status=201)


async def close_slot(request: web.Request) -> web.Response:
    slot, problem = slot_or_error(request)
    if problem:
        return problem
    del slots(request)[request.match_info["slot"]]
    return web.Response(status=204)


def setup_pairing_routes(app: web.Application) -> None:
    app["pairing_slots"] = {}
    app.router.add_post("/api/pairing", open_slot)
    app.router.add_get("/api/pairing/{slot}", get_slot)
    app.router.add_put("/api/pairing/{slot}/response", put_response)
    app.router.add_delete("/api/pairing/{slot}", close_slot)
