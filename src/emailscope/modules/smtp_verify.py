"""SMTP recipient verification against the domain's real mail exchangers.

Sends ``RCPT TO`` only — no message body is ever transmitted. Timeouts and
greylisting are reported as *unknown* rather than as a negative.
"""

from __future__ import annotations

import asyncio
import socket

import dns.asyncresolver
import dns.exception
import dns.resolver

from emailscope.context import Context
from emailscope.models import Finding

CONNECT_TIMEOUT = 8.0
SENDER = "probe@emailscope.local"
_HELO = b"emailscope.local"

EXISTS = "exists"
MISSING = "not_exists"
UNKNOWN = "unknown"

_POSITIVE = {250, 251}
_HARD_REJECT = {550, 551, 552, 553, 554, 556, 521}


async def _mx_hosts(domain: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 6.0
    resolver.lifetime = 6.0
    try:
        answer = await resolver.resolve(domain, "MX")
    except (dns.exception.DNSException, OSError):
        return []
    hosts: list[tuple[int, str]] = []
    for record in answer:
        host = record.exchange.to_text().rstrip(".")
        if host:
            hosts.append((record.preference, host))
    hosts.sort()
    return [host for _, host in hosts]


async def _probe_one(host: str, address: str) -> tuple[str, str]:
    """Talk SMTP to ``host``. Returns ``(verdict, detail)``."""

    def run() -> tuple[str, str]:
        try:
            with socket.create_connection((host, 25), timeout=CONNECT_TIMEOUT) as sock:
                sock.settimeout(CONNECT_TIMEOUT)
                stream = sock.makefile("rb")

                def read_reply() -> list[str]:
                    lines: list[str] = []
                    while True:
                        line = stream.readline()
                        if not line:
                            break
                        text = line.decode("utf-8", "replace").rstrip()
                        lines.append(text)
                        if len(line) < 4 or line[3:4] != b"-":
                            break
                    return lines

                def code(reply: list[str]) -> int:
                    if reply and reply[0][:3].isdigit():
                        return int(reply[0][:3])
                    return 0

                banner = read_reply()
                if code(banner) not in (220, 0):
                    return UNKNOWN, "unexpected banner: " + (banner[0] if banner else "empty")

                sock.sendall(b"HELO " + _HELO + b"\r\n")
                helo = read_reply()
                if code(helo) not in _POSITIVE:
                    return UNKNOWN, "HELO rejected: " + (helo[0] if helo else "no reply")

                sock.sendall(f"MAIL FROM:<{SENDER}>\r\n".encode())
                sender = read_reply()
                if code(sender) not in _POSITIVE:
                    return UNKNOWN, "sender rejected: " + (sender[0] if sender else "no reply")

                sock.sendall(f"RCPT TO:<{address}>\r\n".encode())
                rcpt = read_reply()
                sock.sendall(b"QUIT\r\n")

                reply_code = code(rcpt)
                detail = rcpt[0] if rcpt else "no reply"
                if reply_code in _POSITIVE:
                    return EXISTS, detail
                if reply_code in _HARD_REJECT:
                    return MISSING, detail
                return UNKNOWN, detail
        except TimeoutError:
            return UNKNOWN, "connection timed out"
        except OSError as exc:
            return UNKNOWN, f"socket error: {exc}"

    return await asyncio.to_thread(run)


async def collect(context: Context) -> Finding:
    identity = context.identity
    if not context.options.smtp:
        return Finding(module="smtp", title="Deliverability", status="skip", summary="Disabled.")
    if not identity.valid or not identity.domain:
        return Finding(
            module="smtp", title="Deliverability", status="skip", summary="Invalid address."
        )

    hosts = await _mx_hosts(identity.domain)
    if not hosts:
        return Finding(
            module="smtp",
            title="Deliverability",
            status="info",
            summary=f"{identity.domain} publishes no MX record.",
            data={"mx": [], "verdict": UNKNOWN},
        )

    attempts: list[dict[str, str]] = []
    verdict = UNKNOWN
    for host in hosts[:3]:
        result, detail = await _probe_one(host, identity.email)
        attempts.append({"mx": host, "verdict": result, "detail": detail[:200]})
        if result in (EXISTS, MISSING):
            verdict = result
            break

    if verdict == EXISTS:
        summary = "Mail server accepted the recipient — the mailbox exists."
        status = "hit"
    elif verdict == MISSING:
        summary = "Mail server rejected the recipient — no such mailbox."
        status = "info"
    else:
        summary = "Could not determine — the server deferred, greylisted or timed out."
        status = "unknown"

    return Finding(
        module="smtp",
        title="Deliverability",
        status=status,
        summary=summary,
        data={"mx": hosts, "verdict": verdict, "attempts": attempts},
    )
