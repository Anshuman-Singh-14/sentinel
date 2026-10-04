"""Tests for the one-file launcher (run.py, ADR 0013).

Standard library only, like the launcher itself, so they run on any host:

    python -m unittest discover -s tests/launcher -v

Docker is never called: every process call goes through `run.run_docker`,
which these tests replace with a fake.
"""

from __future__ import annotations

import io
import itertools
import subprocess  # nosec B404
import sys
import tempfile
import unittest
import urllib.error
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import run

EXAMPLE = (
    "# Sentinel environment configuration.\n"
    "# replace every CHANGE_ME value\n"
    "ENVIRONMENT=development\n"
    "POSTGRES_PASSWORD=CHANGE_ME\n"
    "# DISABLED_SECRET=CHANGE_ME\n"
    "REDIS_PASSWORD=CHANGE_ME\n"
    "API_PORT=8000\n"
)


def counter() -> Callable[[], str]:
    numbers = itertools.count(1)
    return lambda: f"token{next(numbers)}"


class FakeDocker:
    """Records docker calls and answers them from a table of canned results."""

    def __init__(self, answers: dict[str, int] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.answers = answers or {}

    def __call__(
        self, docker: str, args: Sequence[str], **_: Any
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        joined = " ".join(args)
        code = next((c for key, c in self.answers.items() if key in joined), 0)
        stdout = "2.29.1\n" if joined == "compose version --short" else ""
        return subprocess.CompletedProcess([docker, *args], code, stdout, "")

    def commands(self) -> list[str]:
        return [" ".join(call) for call in self.calls]


@contextmanager
def checkout(with_env: bool = False) -> Iterator[Path]:
    """A temporary repo root with .env.example (and optionally .env)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".env.example").write_text(EXAMPLE, encoding="utf-8")
        if with_env:
            (root / ".env").write_text("API_PORT=8000\n", encoding="utf-8")
        with mock.patch.object(run, "ROOT", root):
            yield root


def quiet(func: Callable[[], Any]) -> tuple[Any, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        result = func()
    return result, out.getvalue(), err.getvalue()


class RenderEnvTests(unittest.TestCase):
    def test_replaces_every_placeholder_and_keeps_other_lines(self) -> None:
        text, generated = run.render_env(EXAMPLE, counter())

        self.assertEqual(generated, 2)
        self.assertIn("POSTGRES_PASSWORD=token1\n", text)
        self.assertIn("REDIS_PASSWORD=token2\n", text)
        self.assertIn("ENVIRONMENT=development\n", text)
        self.assertIn("# DISABLED_SECRET=CHANGE_ME\n", text)  # comments untouched
        self.assertIn("# replace every CHANGE_ME value\n", text)

    def test_crlf_checkout_becomes_lf(self) -> None:
        text, generated = run.render_env(EXAMPLE.replace("\n", "\r\n"), counter())

        self.assertEqual(generated, 2)
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("API_PORT=8000\n"))

    def test_real_example_has_placeholders_and_secrets_are_long_hex(self) -> None:
        example = (Path(__file__).resolve().parents[2] / ".env.example").read_text("utf-8")
        text, generated = run.render_env(example, run.new_secret)

        self.assertGreaterEqual(generated, 4)
        self.assertNotIn("=CHANGE_ME\n", text)
        secret = next(
            line.split("=", 1)[1]
            for line in text.splitlines()
            if line.startswith("REDIS_PASSWORD=")
        )
        self.assertRegex(secret, r"^[0-9a-f]{64}$")

    def test_secrets_are_unique(self) -> None:
        self.assertEqual(len({run.new_secret() for _ in range(50)}), 50)


class CreateEnvTests(unittest.TestCase):
    def test_creates_env_when_missing(self) -> None:
        with checkout() as root:
            self.assertEqual(run.create_env(root, counter()), 2)
            self.assertIn("POSTGRES_PASSWORD=token1", (root / ".env").read_text("utf-8"))

    def test_never_overwrites_an_existing_env(self) -> None:
        with checkout(with_env=True) as root:
            self.assertIsNone(run.create_env(root, counter()))
            self.assertEqual((root / ".env").read_text("utf-8"), "API_PORT=8000\n")

    def test_missing_example_is_a_clear_error(self) -> None:
        with checkout() as root:
            (root / ".env.example").unlink()
            with self.assertRaisesRegex(run.LauncherError, "env.example is missing"):
                run.create_env(root)

    def test_start_reports_the_count_but_never_prints_secrets(self) -> None:
        fake = FakeDocker()
        with (
            checkout() as root,
            mock.patch("run.shutil.which", return_value="/usr/bin/docker"),
            mock.patch.object(run, "run_docker", fake),
            mock.patch.object(run, "wait_for_health", return_value=True),
            mock.patch("run.webbrowser.open"),
            mock.patch("run.sys.stdin.isatty", return_value=False),
        ):
            code, out, err = quiet(lambda: run.main([]))
            secret_values = [
                line.split("=", 1)[1]
                for line in (root / ".env").read_text("utf-8").splitlines()
                if "PASSWORD=" in line and not line.startswith("#")
            ]

        self.assertEqual(code, 0)
        self.assertIn("Created .env with 2 generated secrets.", out)
        self.assertEqual(len(secret_values), 2)
        for value in secret_values:
            self.assertNotIn(value, out + err)
            self.assertFalse(any(value in " ".join(call) for call in fake.calls))


class ParsingTests(unittest.TestCase):
    def test_compose_versions(self) -> None:
        cases = {
            "2.29.1": (2, 29, 1),
            "v2.24.0-desktop.1\n": (2, 24, 0),
            "5.5.1": (5, 5, 1),
            "2.24": (2, 24, 0),
            "": None,
            "garbage": None,
            "Docker Compose version 1.2.3": None,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(run.parse_compose_version(text), expected)

    def test_version_comparison_is_numeric(self) -> None:
        self.assertGreater((2, 100, 0), run.MIN_COMPOSE_VERSION)
        self.assertGreater((5, 0, 0), run.MIN_COMPOSE_VERSION)
        self.assertLess((2, 23, 9), run.MIN_COMPOSE_VERSION)

    def test_flag_defaults(self) -> None:
        args = run.parse_args([])
        self.assertEqual(
            (args.prod, args.no_lab, args.stop, args.reset, args.logs),
            (False, False, False, False, False),
        )

    def test_each_flag(self) -> None:
        for flag in ("prod", "no_lab", "stop", "reset", "logs"):
            with self.subTest(flag=flag):
                args = run.parse_args(["--" + flag.replace("_", "-")])
                self.assertTrue(getattr(args, flag))

    def test_stop_reset_and_logs_are_mutually_exclusive(self) -> None:
        for pair in (["--stop", "--reset"], ["--stop", "--logs"], ["--reset", "--logs"]):
            with self.subTest(pair=pair), self.assertRaises(SystemExit):
                quiet(lambda pair=pair: run.parse_args(pair))  # type: ignore[misc]

    def test_compose_args(self) -> None:
        self.assertEqual(run.compose_args(prod=False, lab=False), ["compose"])
        self.assertEqual(run.compose_args(prod=False, lab=True), ["compose", "--profile", "lab"])
        self.assertEqual(
            run.compose_args(prod=True, lab=True),
            [
                "compose",
                "-f",
                "docker-compose.yml",
                "-f",
                "docker-compose.prod.yml",
                "--profile",
                "lab",
            ],
        )

    def test_usernames(self) -> None:
        for name in ("admin", "Admin.One", "a_b-c", "x" * 64):
            self.assertTrue(run.valid_username(name), name)
        for name in ("ab", "x" * 65, "-admin", "--help", "bad name", "a;rm", "", "$(id)"):
            self.assertFalse(run.valid_username(name), name)

    def test_env_values_and_ports(self) -> None:
        with checkout() as root:
            (root / ".env").write_text(
                "# comment\nAPI_PORT=9000\nFRONTEND_PORT=\nBAD=x\n", encoding="utf-8"
            )
            values = run.read_env_values(root / ".env")
        self.assertEqual(run.env_port(values, "API_PORT", 8000), 9000)
        self.assertEqual(run.env_port(values, "FRONTEND_PORT", 5173), 5173)  # empty -> default
        with self.assertRaises(run.LauncherError):
            run.env_port(values, "BAD", 1)


class PreflightTests(unittest.TestCase):
    def test_docker_missing(self) -> None:
        with mock.patch("run.shutil.which", return_value=None):
            code, _, err = quiet(lambda: run.main([]))
        self.assertEqual(code, 1)
        self.assertIn("Docker is not installed", err)
        self.assertIn("docker-desktop", err)

    def test_daemon_not_running(self) -> None:
        fake = FakeDocker({"info": 1})
        with (
            mock.patch("run.shutil.which", return_value="/usr/bin/docker"),
            mock.patch.object(run, "run_docker", fake),
        ):
            code, _, err = quiet(lambda: run.main([]))
        self.assertEqual(code, 1)
        self.assertIn("engine isn't running", err)

    def test_daemon_timeout_counts_as_not_running(self) -> None:
        def hang(*_: Any, **__: Any) -> Any:
            raise subprocess.TimeoutExpired("docker info", 30)

        with (
            mock.patch("run.shutil.which", return_value="/usr/bin/docker"),
            mock.patch.object(run, "run_docker", hang),
        ):
            code, _, err = quiet(lambda: run.main([]))
        self.assertEqual(code, 1)
        self.assertIn("engine isn't running", err)

    def test_old_compose_is_refused(self) -> None:
        def old(docker: str, args: Sequence[str], **_: Any) -> Any:
            out = "2.20.2" if "version" in args else ""
            return subprocess.CompletedProcess(args, 0, out, "")

        with (
            mock.patch("run.shutil.which", return_value="/usr/bin/docker"),
            mock.patch.object(run, "run_docker", old),
        ):
            code, _, err = quiet(lambda: run.main([]))
        self.assertEqual(code, 1)
        self.assertIn("v2.24+ is required; found v2.20.2", err)


class CommandTests(unittest.TestCase):
    def run_main(
        self,
        argv: list[str],
        fake: FakeDocker,
        *,
        tty: bool = False,
        with_env: bool = True,
        answers: Sequence[str] = (),
    ) -> tuple[int, str, str]:
        replies = iter(answers)
        with (
            checkout(with_env=with_env),
            mock.patch("run.shutil.which", return_value="/usr/bin/docker"),
            mock.patch.object(run, "run_docker", fake),
            mock.patch.object(run, "wait_for_health", return_value=True),
            mock.patch("run.webbrowser.open") as browser,
            mock.patch("run.sys.stdin.isatty", return_value=tty),
            mock.patch("builtins.input", lambda _prompt: next(replies)),
        ):
            result: tuple[int, str, str] = quiet(lambda: run.main(argv))
            self.browser = browser
        return result

    def test_default_start_uses_lab_profile_and_opens_browser(self) -> None:
        fake = FakeDocker()
        code, out, _ = self.run_main([], fake)

        self.assertEqual(code, 0)
        self.assertIn(
            "compose --profile lab up --build -d --wait --wait-timeout 600", fake.commands()
        )
        self.assertIn("An admin account already exists.", out)
        self.browser.assert_called_once_with("http://localhost:5173")

    def test_no_lab_and_prod(self) -> None:
        fake = FakeDocker()
        code, _, _ = self.run_main(["--prod", "--no-lab"], fake)
        self.assertEqual(code, 0)
        up = next(c for c in fake.commands() if " up " in c)
        self.assertTrue(
            up.startswith("compose -f docker-compose.yml -f docker-compose.prod.yml up")
        )
        self.assertNotIn("--profile", up)
        self.browser.assert_called_once_with("http://localhost:8080")

    def test_failed_up_is_reported_with_its_exit_code(self) -> None:
        code, _, err = self.run_main([], FakeDocker({" up ": 17}))
        self.assertEqual(code, 17)
        self.assertIn("docker compose up` failed", err)

    def test_no_admin_and_no_tty_prints_the_manual_command(self) -> None:
        fake = FakeDocker({"admin-exists": run.NO_ADMIN_EXIT_CODE})
        code, out, _ = self.run_main([], fake, tty=False)

        self.assertEqual(code, 0)
        self.assertIn("app.cli create-admin --username admin", out)
        self.assertFalse(any("create-admin" in c for c in fake.commands()))

    def test_no_admin_with_tty_creates_one_interactively(self) -> None:
        fake = FakeDocker({"admin-exists": run.NO_ADMIN_EXIT_CODE})
        code, _, _ = self.run_main([], fake, tty=True, answers=["bad name", "Alice"])

        self.assertEqual(code, 0)
        create = fake.calls[-1]
        self.assertEqual(
            create[-7:], ["api", "python", "-m", "app.cli", "create-admin", "--username", "Alice"]
        )
        self.assertNotIn("-T", create)  # interactive, so the password prompt gets a TTY
        self.assertFalse(any("password" in arg.lower() for arg in create))

    def test_stop_includes_lab_profile(self) -> None:
        fake = FakeDocker()
        code, _, _ = self.run_main(["--stop", "--no-lab"], fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.commands()[-1], "compose --profile lab down")

    def test_stop_without_env_is_explained(self) -> None:
        code, _, err = self.run_main(["--stop"], FakeDocker(), with_env=False)
        self.assertEqual(code, 1)
        self.assertIn("No .env", err)

    def test_reset_declined_deletes_nothing(self) -> None:
        fake = FakeDocker()
        code, out, _ = self.run_main(["--reset"], fake, tty=True, answers=[""])
        self.assertEqual(code, 1)
        self.assertIn("nothing was deleted", out)
        self.assertFalse(any("down" in c for c in fake.commands()))

    def test_reset_confirmed_removes_volumes(self) -> None:
        fake = FakeDocker()
        code, _, _ = self.run_main(["--reset"], fake, tty=True, answers=["y"])
        self.assertEqual(code, 0)
        self.assertEqual(fake.commands()[-1], "compose --profile lab down -v")

    def test_reset_refuses_without_a_terminal(self) -> None:
        fake = FakeDocker()
        code, _, err = self.run_main(["--reset"], fake, tty=False)
        self.assertEqual(code, 1)
        self.assertIn("interactive terminal", err)
        self.assertFalse(any("down" in c for c in fake.commands()))

    def test_logs(self) -> None:
        fake = FakeDocker()
        code, _, _ = self.run_main(["--logs", "--prod"], fake)
        self.assertEqual(code, 0)
        self.assertTrue(fake.commands()[-1].endswith("--profile lab logs -f --tail 200"))


class HealthTests(unittest.TestCase):
    def test_waits_until_healthy(self) -> None:
        responses = iter([urllib.error.URLError("refused"), ConnectionResetError(), 200])

        @contextmanager
        def opener(url: str, timeout: float) -> Iterator[Any]:
            item = next(responses)
            if isinstance(item, Exception):
                raise item
            yield mock.Mock(status=item)

        sleeps: list[float] = []
        self.assertTrue(
            run.wait_for_health(
                "http://127.0.0.1:8000/health",
                60,
                opener=opener,
                sleep=sleeps.append,
                clock=lambda: 0.0,
            )
        )
        self.assertEqual(len(sleeps), 2)

    def test_gives_up_at_the_deadline(self) -> None:
        def opener(url: str, timeout: float) -> Any:
            raise urllib.error.URLError("refused")

        ticks = iter(range(100))
        self.assertFalse(
            run.wait_for_health(
                "http://127.0.0.1:8000/health",
                5,
                opener=opener,
                sleep=lambda _: None,
                clock=lambda: float(next(ticks)),
            )
        )


if __name__ == "__main__":
    unittest.main()
