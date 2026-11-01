"""RFC 2136 dynamic update through the `nsupdate` tool."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

_ALGOS = {"hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"}
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


class NsupdateError(Exception):
    pass


def txt_rdata(value: str) -> str:
    """A TXT value as the quoted character-strings nsupdate wants (at most 255 bytes each; backslash and quote escaped)."""
    if not value.isascii() or any(ord(c) < 0x20 or ord(c) == 0x7f for c in value):
        raise NsupdateError("a TXT value must be printable ASCII here")
    chunks = [value[i:i + 255] for i in range(0, len(value), 255)] or [""]
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)


def fqdn(name: str) -> str:
    return name if name.endswith(".") else name + "."


def script(server: str | None, zone: str | None, ttl: int, removes: list[tuple[str, str]], adds: list[tuple[str, str]],
           replace_all: list[str] = ()) -> str:
    """The nsupdate input: one transaction. `replace_all` names are emptied first (only for names that are ours alone)."""
    lines = []
    if server:
        lines.append(f"server {server}")
    if zone:
        lines.append(f"zone {fqdn(zone)}")
    for name in replace_all:
        lines.append(f"update delete {fqdn(name)} TXT")
    for name, value in removes:
        lines.append(f"update delete {fqdn(name)} TXT {txt_rdata(value)}")
    for name, value in adds:
        lines.append(f"update add {fqdn(name)} {int(ttl)} TXT {txt_rdata(value)}")
    lines.append("send")
    lines.append("")
    return "\n".join(lines)


@dataclass
class Key:
    """A TSIG key: a file `nsupdate -k` reads, or name:secret[:algorithm] made into a temporary file (never on the command line)."""

    file: str | None = None
    name: str | None = None
    secret: str | None = None
    algorithm: str = "hmac-sha256"

    @classmethod
    def parse(cls, spec: str) -> "Key":
        """`[algorithm:]name:secret` (what `nsupdate -y` takes)."""
        parts = spec.split(":")
        algorithm = "hmac-sha256"
        if len(parts) == 3:
            algorithm, parts = parts[0].lower(), parts[1:]
        if len(parts) != 2 or algorithm not in _ALGOS or not _NAME.match(parts[0]) or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", parts[1]):
            raise NsupdateError("a key is [algorithm:]name:secret, the secret in base64")
        return cls(name=parts[0], secret=parts[1], algorithm=algorithm)


class NsupdatePublisher:
    def __init__(self, server: str | None = None, port: int | None = None, zone: str | None = None, key: Key | None = None,
                 tcp: bool = True, executable: str | None = None, runner=None):
        self.server, self.port, self.zone, self.key, self.tcp = server, port, zone, key, tcp
        self.executable = executable or shutil.which("nsupdate")
        self._run = runner or subprocess.run

    def apply(self, removes: list[tuple[str, str]], adds: list[tuple[str, str]], ttl: int, replace_all: list[str] = ()) -> None:
        if not self.executable:
            raise NsupdateError("nsupdate is not installed (it is part of BIND's tools: dnsutils, bind-utils, knot-dnsutils, ...)")
        text = script(self.server, self.zone, ttl, removes, adds, replace_all)
        cmd = [self.executable]
        if self.tcp:
            cmd.append("-v")
        if self.port:
            cmd += ["-p", str(self.port)]
        tmp = None
        try:
            if self.key and self.key.file:
                cmd += ["-k", self.key.file]
            elif self.key and self.key.secret:
                fd, tmp = tempfile.mkstemp(prefix="nsupdate-key-")
                with os.fdopen(fd, "w") as f:
                    f.write(f'key "{self.key.name}" {{ algorithm {self.key.algorithm}; secret "{self.key.secret}"; }};\n')
                cmd += ["-k", tmp]
            done = self._run(cmd, input=text, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired as e:
            raise NsupdateError("nsupdate did not finish in 60 seconds") from e
        finally:
            if tmp:
                os.unlink(tmp)
        if done.returncode != 0:
            raise NsupdateError("nsupdate failed: " + (done.stderr or done.stdout or f"exit {done.returncode}").strip()[:400])
