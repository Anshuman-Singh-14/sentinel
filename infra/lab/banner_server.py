"""Lab banner server: a teaching target for Sentinel's port scanner.

It listens on classic service ports and sends the *greeting banner* an old
server would send, then closes the connection after a short read. Nothing
behind the banner is real: no authentication, no file transfer, no shell, no
mail relay. That makes it safe to run while still exercising banner grabbing,
service fingerprinting and banner-based CVE matching (with exactly the
"banners can lie" caveat the findings explain).

Standard library only. Each connection is capped in time and bytes read.
"""

import asyncio
import os
import signal

# port -> greeting. Versions are deliberately old and well documented in NVD.
BANNERS: dict[int, bytes] = {
    21: b"220 (vsFTPd 2.3.4)\r\n",
    22: b"SSH-2.0-OpenSSH_7.4\r\n",
    23: b"\xff\xfd\x18\xff\xfd\x20Ubuntu 14.04 LTS\r\nlab-banners login: ",
    25: b"220 lab-banners.local ESMTP Exim 4.87 Ubuntu\r\n",
    # MySQL protocol v10 handshake: length, sequence, protocol, version string.
    3306: b"\x4a\x00\x00\x00\x0a5.5.62-0ubuntu0.14.04.1\x00" + b"\x00" * 64,
}

READ_LIMIT = 256
READ_TIMEOUT = 3.0


async def handle(port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(BANNERS[port])
        await writer.drain()
        # Read (and discard) whatever the client sends, bounded, then hang up.
        try:
            await asyncio.wait_for(reader.read(READ_LIMIT), timeout=READ_TIMEOUT)
        except TimeoutError:
            pass
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def main() -> None:
    host = os.environ.get("LAB_BIND", "0.0.0.0")  # noqa: S104  (lab container only)
    servers = []
    for port in BANNERS:
        servers.append(
            await asyncio.start_server(lambda r, w, p=port: handle(p, r, w), host, port)
        )
        print(f"lab-banners listening on {host}:{port}", flush=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    for server in servers:
        server.close()


if __name__ == "__main__":
    asyncio.run(main())
