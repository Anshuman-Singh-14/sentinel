#!/usr/bin/env python3
"""Start Sentinel with one command: ``python run.py``.

    python run.py              build and start the dev stack with the lab targets
    python run.py --no-lab     ... without the lab targets
    python run.py --prod       production profile (http://localhost:8080)
    python run.py --logs       follow the logs
    python run.py --stop       stop everything (data is kept)
    python run.py --reset      stop and DELETE all data (asks first)

Standard library only (Python 3.10+), so a fresh clone needs nothing but Docker.
On a first run it creates ``.env`` with random secrets, starts the stack, waits
for the API, offers to create the first admin, and opens the browser.

Security notes (ADR 0013): this is the one file allowed to start processes.
It runs on the operator's own machine and only drives the Docker CLI, always
with an argument list (never a shell string), and from an absolute path. The
admin password is typed into the backend CLI's own prompt and never appears
on a command line. Generated secrets are written to ``.env`` and never printed.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil

# The launcher is the one place allowed to start processes (ADR 0013).
import subprocess  # nosec B404
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

if sys.version_info < (3, 10):  # noqa: UP036  (the guard is the point: clear message on old Python)
    sys.exit("Sentinel's launcher needs Python 3.10 or newer.")

ROOT = Path(__file__).resolve().parent

# `!reset` / `!override` in docker-compose.prod.yml need Compose v2.24+.
MIN_COMPOSE_VERSION = (2, 24, 0)
PROD_FILES = ["-f", "docker-compose.yml", "-f", "docker-compose.prod.yml"]
# Matches the backend's USERNAME_INPUT_PATTERN (app/core/auth/users.py). The
# first character can't be "-", so the value can never be read as an option.
USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
# `python -m app.cli admin-exists` exits with this when there is no admin.
NO_ADMIN_EXIT_CODE = 3
PLACEHOLDER_SUFFIX = "=CHANGE_ME"

INFO_TIMEOUT = 30  # seconds, for quick read-only docker calls
UP_WAIT_TIMEOUT = 600  # seconds compose waits for health checks (first build is slow)
HEALTH_TIMEOUT = 120  # seconds to wait for /health after `up` returns


class LauncherError(Exception):
    """A problem the operator can fix. Printed without a traceback."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# --- Pure helpers (unit tested) ---------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python run.py",
        description="Start, stop or reset the Sentinel stack with Docker Compose.",
    )
    parser.add_argument(
        "--prod", action="store_true", help="use the production profile (http://localhost:8080)"
    )
    parser.add_argument("--no-lab", action="store_true", help="don't start the lab scan targets")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--stop", action="store_true", help="stop the stack (data is kept)")
    action.add_argument(
        "--reset", action="store_true", help="stop the stack and delete all data (asks first)"
    )
    action.add_argument("--logs", action="store_true", help="follow the logs (Ctrl+C to quit)")
    return parser.parse_args(argv)


def parse_compose_version(text: str) -> tuple[int, int, int] | None:
    """Parse `docker compose version --short` output: "2.29.1", "v2.24.0-desktop.1"."""
    match = re.match(r"\s*v?(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def compose_args(*, prod: bool, lab: bool) -> list[str]:
    """The `docker compose ...` prefix shared by every command."""
    args = ["compose"]
    if prod:
        args += PROD_FILES
    if lab:
        args += ["--profile", "lab"]
    return args


def render_env(example: str, token: Callable[[], str]) -> tuple[str, int]:
    """Replace every `KEY=CHANGE_ME` line with a fresh token (as init-env does).

    Returns the new text (LF line endings, so Compose reads it exactly) and the
    number of secrets generated. Comment lines are left alone.
    """
    lines: list[str] = []
    generated = 0
    for line in example.splitlines():  # also strips CR from a CRLF checkout
        if line.endswith(PLACEHOLDER_SUFFIX) and not line.lstrip().startswith("#"):
            lines.append(line[: -len(PLACEHOLDER_SUFFIX)] + "=" + token())
            generated += 1
        else:
            lines.append(line)
    return "\n".join(lines) + "\n", generated


def new_secret() -> str:
    # 64 hex characters: URL-safe, because the passwords go into connection URLs.
    return secrets.token_hex(32)


def create_env(root: Path, token: Callable[[], str] = new_secret) -> int | None:
    """Create `.env` from `.env.example`. Returns the secret count, or None if it exists.

    O_EXCL makes "never overwrite" hold even if two launchers race, and mode
    0600 keeps the file readable by its owner only (on POSIX; Windows ignores it
    and relies on the user profile's ACLs).
    """
    target = root / ".env"
    if target.exists():
        return None
    try:
        example = (root / ".env.example").read_text(encoding="utf-8")
    except FileNotFoundError:
        raise LauncherError(
            ".env.example is missing: is this a complete Sentinel checkout?"
        ) from None
    text, generated = render_env(example, token)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return None
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return generated


def read_env_values(path: Path) -> dict[str, str]:
    """Minimal KEY=value reader for the few settings the launcher needs (ports)."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def env_port(values: dict[str, str], key: str, default: int) -> int:
    raw = values.get(key) or str(default)
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise LauncherError(f"{key} in .env must be a port number (1-65535), not {raw!r}.")
    return int(raw)


def valid_username(name: str) -> bool:
    return USERNAME_RE.fullmatch(name) is not None


def manual_admin_command(prod: bool) -> str:
    files = " -f docker-compose.yml -f docker-compose.prod.yml" if prod else ""
    return f"docker compose{files} exec api python -m app.cli create-admin --username admin"


# --- Docker and the outside world -------------------------------------------


def find_docker() -> str:
    docker = shutil.which("docker")
    if docker is None:
        hint = (
            "  On Windows: run `wsl --install` in an admin PowerShell, reboot, then install\n"
            "  Docker Desktop.\n"
            if os.name == "nt"
            else ""
        )
        raise LauncherError(
            "Docker is not installed (no `docker` on PATH).\n"
            "  Install Docker Desktop: https://www.docker.com/products/docker-desktop/\n"
            f"{hint}"
            "  Then open a new terminal and run `python run.py` again."
        )
    return docker


def run_docker(
    docker: str,
    args: Sequence[str],
    *,
    timeout: float | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """The launcher's only process call (ADR 0013).

    An argument list with shell=False: no shell ever parses it, so nothing in
    it can be read as shell syntax. `docker` is an absolute path from
    shutil.which. Interactive calls (admin prompt, logs -f) pass no timeout and
    end when the operator ends them.
    """
    # Our buffered output must reach the screen before Docker starts writing,
    # or messages appear out of order when stdout is a pipe.
    sys.stdout.flush()
    # Fixed argv, no shell: the documented exception in ADR 0013.
    return subprocess.run(  # noqa: S603  # nosec B603
        [docker, *args],
        cwd=ROOT,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=capture,
        timeout=timeout,
    )


def preflight() -> str:
    """Check Docker is installed and running and Compose is new enough."""
    docker = find_docker()
    not_running = LauncherError(
        "Docker is installed but its engine isn't running.\n"
        "  Start Docker Desktop (or the Docker service), wait until it says\n"
        "  'Engine running', then run `python run.py` again."
    )
    try:
        info = run_docker(
            docker, ["info", "--format", "{{.ServerVersion}}"], timeout=INFO_TIMEOUT, capture=True
        )
    except subprocess.TimeoutExpired:
        raise not_running from None
    if info.returncode != 0:
        raise not_running
    try:
        result = run_docker(
            docker, ["compose", "version", "--short"], timeout=INFO_TIMEOUT, capture=True
        )
    except subprocess.TimeoutExpired:
        result = None
    version = parse_compose_version(result.stdout) if result and result.returncode == 0 else None
    wanted = ".".join(map(str, MIN_COMPOSE_VERSION[:2]))
    if version is None:
        raise LauncherError(
            f"Docker Compose v{wanted}+ is required, but `docker compose` "
            "was not found. Update Docker Desktop or install the Compose plugin."
        )
    if version < MIN_COMPOSE_VERSION:
        found = ".".join(map(str, version))
        raise LauncherError(
            f"Docker Compose v{wanted}+ is required; found v{found}. "
            "Update Docker Desktop or the Compose plugin."
        )
    return docker


def wait_for_health(
    url: str,
    timeout: float = HEALTH_TIMEOUT,
    *,
    interval: float = 2.0,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """Poll the API health endpoint until it answers 200, or give up."""
    deadline = clock() + timeout
    while True:
        try:
            # A fixed http://127.0.0.1 URL built from a validated port number.
            with opener(url, timeout=5) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            pass  # not up yet (connection refused, reset, 5xx)
        if clock() >= deadline:
            return False
        sleep(interval)


def ask_username(attempts: int = 3) -> str:
    for _ in range(attempts):
        name = input("Admin username [admin]: ").strip() or "admin"
        if valid_username(name):
            return name
        print(
            "  Usernames are 3-64 characters: letters, digits, '.', '_' or '-',"
            " starting with a letter or digit."
        )
    raise LauncherError("No valid username entered.")


def ensure_admin(docker: str, base: list[str], *, prod: bool, interactive: bool) -> None:
    """Offer to create the first admin when the database has none."""
    try:
        probe = run_docker(
            docker,
            [*base, "exec", "-T", "api", "python", "-m", "app.cli", "admin-exists"],
            timeout=INFO_TIMEOUT * 2,
            capture=True,
        )
        code = probe.returncode
    except subprocess.TimeoutExpired:
        code = -1
    if code == 0:
        print("An admin account already exists.")
        return
    if code != NO_ADMIN_EXIT_CODE:
        print(
            "Could not check for an admin account. To create one:\n  " + manual_admin_command(prod)
        )
        return
    if not interactive:
        print(
            "No admin account yet. In an interactive terminal, run:\n  "
            + manual_admin_command(prod)
        )
        return
    print("\nNo admin account yet. Let's create the first one.")
    try:
        username = ask_username()
    except EOFError:
        # isatty() can't be trusted alone: on Windows the NUL device reports
        # itself as a terminal. No input means no prompt, not a traceback.
        print(
            "\nNo input available. To create the admin later, run:\n  " + manual_admin_command(prod)
        )
        return
    # The backend CLI asks for the password itself (twice, not echoed), so it
    # never appears in argv, shell history or `ps` output.
    created = run_docker(
        docker,
        [*base, "exec", "api", "python", "-m", "app.cli", "create-admin", "--username", username],
    )
    if created.returncode != 0:
        print("Admin creation failed (see above). Try again with:\n  " + manual_admin_command(prod))


def confirm_reset() -> bool:
    try:
        answer = input(
            "This deletes ALL Sentinel data (users, runs, reports, audit log). Continue? [y/N]: "
        )
    except EOFError:
        return False  # no answer is "No"
    return answer.strip().lower() in {"y", "yes"}


# --- Commands ----------------------------------------------------------------


def start(docker: str, args: argparse.Namespace) -> int:
    generated = create_env(ROOT)
    if generated is None:
        print("Using the existing .env.")
    else:
        print(f"Created .env with {generated} generated secrets.")

    lab = not args.no_lab
    base = compose_args(prod=args.prod, lab=lab)
    mode = "production" if args.prod else "development"
    print(
        f"Starting Sentinel ({mode}{', with lab targets' if lab else ''}). "
        "The first build takes 3-6 minutes..."
    )
    up = run_docker(
        docker, [*base, "up", "--build", "-d", "--wait", "--wait-timeout", str(UP_WAIT_TIMEOUT)]
    )
    if up.returncode != 0:
        raise LauncherError(
            "`docker compose up` failed (see above). Inspect with `python run.py --logs`.",
            up.returncode,
        )

    values = read_env_values(ROOT / ".env")
    if args.prod:
        port = env_port(values, "PROD_PORT", 8080)
        health_url, app_url = f"http://127.0.0.1:{port}/health", f"http://localhost:{port}"
    else:
        api_port = env_port(values, "API_PORT", 8000)
        health_url = f"http://127.0.0.1:{api_port}/health"
        app_url = f"http://localhost:{env_port(values, 'FRONTEND_PORT', 5173)}"
    if not wait_for_health(health_url):
        raise LauncherError(
            f"The API did not become healthy at {health_url}. Inspect with `python run.py --logs`."
        )

    ensure_admin(docker, base, prod=args.prod, interactive=sys.stdin.isatty())
    print(f"\nSentinel is running: {app_url}")
    print("Stop with `python run.py --stop`; follow logs with `python run.py --logs`.")
    webbrowser.open(app_url)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        docker = preflight()
        if args.stop or args.reset or args.logs:
            if not (ROOT / ".env").exists():
                raise LauncherError(
                    "No .env here, so Sentinel was never started from this "
                    "checkout. Run `python run.py` first."
                )
            # Stop/reset always include the lab profile, or its containers stay up.
            every = compose_args(prod=args.prod, lab=True)
            if args.stop:
                return run_docker(docker, [*every, "down"]).returncode
            if args.reset:
                if not sys.stdin.isatty():
                    raise LauncherError("--reset needs an interactive terminal to confirm.")
                if not confirm_reset():
                    print("Cancelled; nothing was deleted.")
                    return 1
                return run_docker(docker, [*every, "down", "-v"]).returncode
            try:
                return run_docker(docker, [*every, "logs", "-f", "--tail", "200"]).returncode
            except KeyboardInterrupt:
                return 0
        return start(docker, args)
    except LauncherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
