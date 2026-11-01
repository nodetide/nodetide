"""Publishing through the DNS provider plugins of acme.sh (https://github.com/acmesh-official/acme.sh/tree/master/dnsapi).

acme.sh is not bundled and not downloaded: point to an installation you already trust (`--acme-home`, default
$LE_WORKING_DIR or ~/.acme.sh). A plugin is a shell file with `dns_<name>_add <fulldomain> <txtvalue>` and
`dns_<name>_rm <fulldomain> <txtvalue>`; it needs acme.sh's helper functions, so the tool sources acme.sh as a library
(its `main` only prints help when given no arguments) and then calls the plugin. Credentials go in the environment, as
for acme.sh itself (a plugin's `_info` lists them; `nodetide dns plugins`); the plugin may save them in the account.conf
of that acme.sh home, exactly as when acme.sh runs it.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_PLUGIN = re.compile(r"^dns_[a-z0-9_]{1,40}$")

# Run one plugin function. The value travels in the environment, not on a command line.
RUNNER = r'''
ACME_HOME=$1; PLUGIN=$2; OP=$3; NAME=$4
export LE_WORKING_DIR="$ACME_HOME"
. "$ACME_HOME/acme.sh" >/dev/null 2>&1
_initpath >/dev/null 2>&1
. "$ACME_HOME/dnsapi/$PLUGIN.sh" || exit 3
"${PLUGIN}_${OP}" "$NAME" "$NT_VALUE"
'''

INFO = r'''
ACME_HOME=$1; PLUGIN=$2
export LE_WORKING_DIR="$ACME_HOME"
. "$ACME_HOME/dnsapi/$PLUGIN.sh" >/dev/null 2>&1 || exit 3
eval "printf '%s\n' \"\$${PLUGIN}_info\""
'''


class AcmeError(Exception):
    pass


def default_home() -> Path:
    return Path(os.environ.get("LE_WORKING_DIR") or Path.home() / ".acme.sh")


def check_plugin(plugin: str) -> str:
    plugin = plugin if plugin.startswith("dns_") else "dns_" + plugin
    if not _PLUGIN.match(plugin):
        raise AcmeError(f"{plugin!r} is not a plugin name (like dns_cf)")
    return plugin


def check_home(home: Path, plugin: str | None = None) -> Path:
    if not (home / "acme.sh").is_file():
        raise AcmeError(f"no acme.sh in {home}: install it (https://github.com/acmesh-official/acme.sh) or pass --acme-home")
    if plugin and not (home / "dnsapi" / f"{plugin}.sh").is_file():
        raise AcmeError(f"{home}/dnsapi/{plugin}.sh does not exist")
    return home


def plugins(home: Path) -> list[str]:
    return sorted(p.stem for p in (home / "dnsapi").glob("dns_*.sh") if _PLUGIN.match(p.stem))


def plugin_info(home: Path, plugin: str, runner=None) -> str:
    done = (runner or subprocess.run)(["sh", "-c", INFO, "sh", str(home), plugin], capture_output=True, text=True, timeout=30)
    return done.stdout.strip() if done.returncode == 0 else ""


class AcmePublisher:
    def __init__(self, plugin: str, home: Path | None = None, env: dict[str, str] | None = None, runner=None):
        self.plugin = check_plugin(plugin)
        self.home = check_home(home or default_home(), self.plugin)
        self.env = env
        self._run = runner or subprocess.run

    def _call(self, op: str, name: str, value: str) -> None:
        env = dict(os.environ if self.env is None else self.env)
        env["NT_VALUE"] = value
        done = self._run(["sh", "-c", RUNNER, "sh", str(self.home), self.plugin, op, name.rstrip(".")],
                         env=env, capture_output=True, text=True, timeout=120)
        if done.returncode != 0:
            detail = (done.stdout + done.stderr).strip().splitlines()[-3:]
            raise AcmeError(f"{self.plugin}_{op} failed for {name}: " + " | ".join(detail)[:400])

    def apply(self, removes: list[tuple[str, str]], adds: list[tuple[str, str]], ttl: int, replace_all: list[str] = ()) -> None:
        """Add first, then remove, so readers always find a record. A plugin removes one value at a time: `replace_all` is
        for nsupdate and is expected to have been turned into explicit removes by the caller."""
        for name, value in adds:
            self._call("add", name, value)
        for name, value in removes:
            self._call("rm", name, value)
