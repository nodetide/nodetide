"""Menu-bar app around the test wallet (macOS).

Runs the wallet on 127.0.0.1 inside this process; "Open wallet" opens it in the default browser through a one-time
launch link, so no HTTP password is typed. The wallet's state file is encrypted with a key kept in the login Keychain
and the HTTP password lives there too. It only makes outbound HTTPS calls to the node you configure.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import threading
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

import keyring
import rumps

SUPPORT = Path(os.environ.get("NODETIDE_WALLET_HOME") or Path.home() / "Library" / "Application Support" / "Nodetide Wallet")
CONFIG = SUPPORT / "config.json"
PASSWORD_SERVICE = "nodetide-test-wallet-app"
DEFAULT_PORT = 4572


def load_config() -> dict:
    try:
        return json.loads(CONFIG.read_text())
    except (OSError, ValueError):
        return {}


def save_config(config: dict) -> None:
    SUPPORT.mkdir(parents=True, exist_ok=True, mode=0o700)
    CONFIG.write_text(json.dumps(config, indent=2))


def valid_url(url: str) -> bool:
    parts = urlsplit(url)
    return bool(parts.hostname) and (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")))


def ask_node(default: str = "") -> str | None:
    while True:
        reply = rumps.Window(
            message="Address of the Nodetide node this wallet talks to (for example https://nt-node.example.org).",
            title="Nodetide Wallet", default_text=default or "https://nt-node.", ok="Save", cancel="Quit", dimensions=(360, 24),
        ).run()
        if not reply.clicked:
            return None
        url = reply.text.strip().rstrip("/")
        if valid_url(url):
            return url
        rumps.alert("Nodetide Wallet", "Use an https:// address.")
        default = url


def derive_verifier(node: str) -> str:
    return node.replace("//nt-node.", "//nt-verifier.", 1)


def http_password() -> str:
    password = keyring.get_password(PASSWORD_SERVICE, "http-password")
    if password is None:
        password = secrets.token_urlsafe(18)
        keyring.set_password(PASSWORD_SERVICE, "http-password", password)
    return password


class Server:
    def __init__(self, wallet_app, port: int) -> None:
        self.wallet_app, self.port = wallet_app, port
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.error: Exception | None = None

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(20)

    def _run(self) -> None:
        from aiohttp import web

        asyncio.set_event_loop(self.loop)

        async def go() -> None:
            runner = web.AppRunner(self.wallet_app.build_app(), handle_signals=False)
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", self.port).start()

        try:
            self.loop.run_until_complete(go())
        except Exception as e:  # port taken, bad state file, ...
            self.error = e
            self.ready.set()
            return
        self.ready.set()
        self.loop.run_forever()

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)


class WalletMenu(rumps.App):
    def __init__(self, wallet_app, server: Server, node: str) -> None:
        super().__init__("Nodetide Wallet", title="🪪", quit_button=None)
        self.wallet_app, self.server, self.port = wallet_app, server, server.port
        self.menu = [
            rumps.MenuItem("Open wallet", callback=self.open_wallet),
            rumps.MenuItem(f"Node: {urlsplit(node).hostname}"),
            None,
            rumps.MenuItem("Change node…", callback=self.change_node),
            rumps.MenuItem("Show data folder", callback=lambda _: os.system(f'open "{SUPPORT}"')),
            None,
            rumps.MenuItem("Quit", callback=self.quit),
        ]

    def open_wallet(self, _=None) -> None:
        webbrowser.open(f"http://localhost:{self.port}{self.wallet_app.launch_path()}")

    def change_node(self, _) -> None:
        node = ask_node(load_config().get("node", ""))
        if node:
            save_config({**load_config(), "node": node})
            os.execv(sys.executable, [sys.executable, *sys.argv[1:]])  # restart with the new node

    def quit(self, _) -> None:
        self.server.stop()
        rumps.quit_application()


def main() -> None:
    config = load_config()
    node = config.get("node")
    if not node:
        node = ask_node()
        if not node:
            return
        config["node"] = node
        save_config(config)
    port = int(config.get("port", DEFAULT_PORT))
    if "start" not in config and not (SUPPORT / "data" / "wallet.json").exists():
        pair = rumps.alert(
            "Nodetide Wallet",
            "Is this your first Nodetide wallet?\n\nChoose \"Pair\" if you already have one (for example on the web): this "
            "Mac then becomes another device of the same identity and shows a code to enter there.",
            ok="Pair with my existing wallet", cancel="New identity",
        )
        config["start"] = "pair" if pair == 1 else "new"
        save_config(config)

    SUPPORT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.environ.update(
        NODE_URL=node,
        VERIFIER_URL=config.get("verifier") or derive_verifier(node),
        WALLET_URL=f"http://localhost:{port}",
        WALLET_PASSWORD=http_password(),
        DATA_DIR=str(SUPPORT / "data"),
        WALLET_KEY_STORE="keychain",
        WALLET_START=config.get("start", ""),  # only matters while the wallet has no state yet
        WALLET_LOCAL_APP="1",
    )
    import app as wallet_app  # reads its settings from the environment when imported

    server = Server(wallet_app, port)
    server.start()
    if server.error:
        rumps.alert("Nodetide Wallet", f"The wallet could not start on port {port}: {server.error}")
        return
    menu = WalletMenu(wallet_app, server, node)
    if "pairing" in wallet_app.wallet.state:  # first start of a pairing wallet: show the code right away
        threading.Timer(1.5, menu.open_wallet).start()
    menu.run()


if __name__ == "__main__":
    main()
