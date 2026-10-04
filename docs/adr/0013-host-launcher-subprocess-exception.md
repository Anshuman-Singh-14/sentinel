# ADR 0013 — Host launcher and its scoped subprocess exception

- **Status:** Accepted
- **Date:** 2026-10-04
- **Phase:** maintenance chore after v1.0.0 (not a build phase)

## Context

Starting Sentinel from a fresh clone took four manual steps: create `.env`
(two scripts, `init-env.sh` and `init-env.ps1`), `docker compose up`, create
the first admin, open the browser. The goal is one command on Windows, macOS
and Linux: `python run.py`, standard library only.

A launcher has to drive the Docker CLI, which means starting a process.
CLAUDE.md rule 1 bans `subprocess`. That rule protects the **server**: the API
and worker handle untrusted input (scan targets, uploads, playbook
parameters), and one shell-injection bug there would hand an attacker a
foothold inside the stack.

## Decision

Allow `subprocess` in **one file only, the repo-root `run.py`**, under these
constraints:

1. **Where it runs.** `run.py` runs on the operator's own machine, under their
   own account. It drives only the Docker CLI they installed, and it never
   ships in an image (the backend build context is `./backend`). It reads
   nothing from the network or from app users.
2. **Argument lists only, `shell=False`.** Every call goes through one helper,
   `_docker()`, which passes a list to `subprocess.run`. No string is ever
   parsed by a shell, so shell metacharacters mean nothing.
3. **Absolute executable path.** The binary comes from `shutil.which("docker")`,
   so later `PATH` lookups (bandit B607) are not involved.
4. **Fixed commands.** The compose arguments are constants. The only operator
   input that reaches argv is the first admin's username. It must match the
   backend's own pattern, `^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`, so it cannot
   start with `-` and be read as an option. It is always a single list element.
5. **No secrets in argv or output.** The admin password is typed into the
   existing CLI's `getpass` prompt inside the container, never passed as an
   argument (03-logging-audit.md section 1). Generated `.env` secrets are
   written to a file created with `O_EXCL` and mode `0600`, and never printed.
6. **Timeouts** on every non-interactive call (rule 7). `up --wait` has its own
   `--wait-timeout`; interactive calls (the admin prompt, `logs -f`) end when
   the operator ends them.

To know whether an admin already exists, the backend gets a read-only CLI
subcommand, `python -m app.cli admin-exists` (exit 0 or 3). The launcher runs
a named command instead of injecting inline Python code into the container.

### What stays the same

Rule 1 still applies, unchanged, to `backend/`, `frontend/`, `infra/` and
`scripts/`. The backend bandit run (`bandit -r app`) never sees `run.py`.
CI lints `run.py` and its tests in a separate step: ruff, mypy `--strict`
for Python 3.10, and bandit `-ll`. Its suppressions are per-line, each
with a reason pointing here: ruff `S603`, bandit `B404` and `B603`.

## Alternatives considered

- **Keep separate `sh` and `ps1` scripts and extend them.** Two
  implementations of the same flow drift apart, and Windows `cmd` users still
  have neither.
- **Makefile or `just`.** Not available on a stock Windows install.
- **Docker SDK for Python.** A pip dependency, which breaks "clone and run",
  and it does not cover Compose.
- **Inline Python via `docker compose exec api python -c ...` for the admin
  check.** It works, but it hides logic in a string the backend tests never
  see. A named CLI subcommand is testable and auditable.

## Consequences

- A fresh clone needs only Docker and Python 3.10+: `python run.py`.
- The init-env scripts and the manual README steps remain as a fallback.
- Any future host-side helper needs its own ADR. This exception does not
  extend to new files by analogy.
