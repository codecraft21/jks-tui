#!/usr/bin/env python3
"""Exercise the built TUI in a real Unix PTY using generated public test data.

Run `cargo build --locked`, then `python3 tests/terminal_smoke.py`.
Requires Python 3 and a Unix terminal API (including Linux/WSL); no pip packages.
"""

import argparse
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 5
ANSI_TOKENS = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b.|[^\x1b]")


class PtyApp:
    """Own the child and PTY, retaining the slave to inspect restored modes."""

    def __init__(self, binary, directory):
        self.binary = binary
        self.directory = directory
        self.output = bytearray()
        self.process = None

    def __enter__(self):
        self.master, self.slave = os.openpty()
        try:
            self.resize(100, 30)
            self.original_modes = termios.tcgetattr(self.slave)

            def controlling_terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)

            self.process = subprocess.Popen(
                [str(self.binary)],
                cwd=self.directory,
                stdin=self.slave,
                stdout=self.slave,
                stderr=self.slave,
                env=dict(os.environ, TERM="xterm-256color"),
                preexec_fn=controlling_terminal,
            )
        except BaseException:
            os.close(self.master)
            os.close(self.slave)
            raise
        return self

    def __exit__(self, *_):
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=TIMEOUT)
        finally:
            os.close(self.master)
            os.close(self.slave)

    def resize(self, width, height):
        fcntl.ioctl(
            self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0)
        )
        if self.process is not None:
            self.process.send_signal(signal.SIGWINCH)

    def read(self, timeout):
        ready, _, _ = select.select([self.master], [], [], timeout)
        if ready:
            try:
                self.output.extend(os.read(self.master, 65536))
            except OSError as error:
                if error.errno != errno.EIO:  # The child may have closed its terminal.
                    raise

    def send(self, keys):
        os.write(self.master, keys)

    def screen(self):
        """Replay the cursor/erase sequences emitted by Ratatui's backend.

        The fixture uses single-column text. This is a small screen reader for
        these checks, not a general ANSI or Unicode terminal emulator.
        """
        height, width = struct.unpack(
            "HHHH", fcntl.ioctl(self.slave, termios.TIOCGWINSZ, b"\0" * 8)
        )[:2]
        grid = [[" "] * width for _ in range(height)]
        y = x = 0
        for token in ANSI_TOKENS.findall(self.output.decode("utf-8", errors="replace")):
            if token.startswith("\x1b["):
                final, parameters = token[-1], token[2:-1]
                if parameters.startswith("?"):
                    continue  # Private terminal modes, including cursor visibility.
                numbers = [int(n or "0") for n in parameters.split(";")]
                count = numbers[0] or 1
                if final in "Hf":
                    y = (numbers[0] or 1) - 1
                    x = ((numbers[1] or 1) if len(numbers) > 1 else 1) - 1
                elif final == "G":
                    x = count - 1
                elif final == "A":
                    y -= count
                elif final == "B":
                    y += count
                elif final == "C":
                    x += count
                elif final == "D":
                    x -= count
                elif final == "J" and numbers[0] in (2, 3):
                    grid = [[" "] * width for _ in range(height)]
                elif final == "K" and 0 <= y < height:
                    start = 0 if numbers[0] in (1, 2) else max(0, x)
                    end = width if numbers[0] in (0, 2) else min(width, x + 1)
                    grid[y][start:end] = [" "] * (end - start)
                continue
            if token.startswith("\x1b"):
                continue
            if token == "\r":
                x = 0
            elif token == "\n":
                y += 1
            elif token >= " ":
                if 0 <= y < height and 0 <= x < width:
                    grid[y][x] = token
                x += 1
        return "\n".join("".join(row) for row in grid)

    def expect(self, *fragments):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            self.read(0.05)
            screen = self.screen()
            if all(fragment in screen for fragment in fragments):
                return
            if self.process.poll() is not None:
                break
        raise AssertionError(
            f"Expected screen text: {fragments!r}; child exit: {self.process.poll()}\n"
            f"Last screen:\n{self.screen()}"
        )

    def assert_restored(self, test):
        try:
            self.process.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired as error:
            raise AssertionError(f"TUI did not exit\n{self.screen()}") from error
        while select.select([self.master], [], [], 0)[0]:
            self.read(0)
        test.assertEqual(self.process.returncode, 0)
        test.assertEqual(termios.tcgetattr(self.slave), self.original_modes)
        for enabled, restored in [
            (b"\x1b[?1049h", b"\x1b[?1049l"),  # Alternate screen.
            (b"\x1b[?25l", b"\x1b[?25h"),  # Cursor visibility.
        ]:
            test.assertIn(enabled, self.output)
            test.assertGreater(self.output.rfind(restored), self.output.rfind(enabled))


class TerminalSmoke(unittest.TestCase):
    binary = ROOT / "target/debug/keystore-tui"

    @classmethod
    def setUpClass(cls):
        if not cls.binary.is_file():
            raise RuntimeError("Build the TUI with cargo build --locked, or pass --binary PATH")
        (ROOT / "target").mkdir(exist_ok=True)

    def exercise(self, exit_key):
        # This fixture contains only a generated public certificate. Recompute
        # its integrity digest for an empty password, avoiding password input.
        body = (ROOT / "tests/fixtures/trusted-cert.jks").read_bytes()[:-20]
        fixture = body + hashlib.sha1(b"Mighty Aphrodite" + body).digest()
        with tempfile.TemporaryDirectory(prefix="terminal-check-", dir=ROOT / "target") as directory:
            Path(directory, "entry.jks").write_bytes(fixture)
            with PtyApp(self.binary, directory) as app:
                app.expect("No keystore selected")
                app.send(b"o")
                app.expect("entry.jks")
                app.send(b"\x1b[B")  # Skip the parent-directory row.
                app.send(b"\r")
                app.expect("root-cert", "Expires")
                app.send(b"\r")
                app.expect("Certificate hierarchy", "Version: 3")
                app.send(b"\t")
                app.expect("Certificate details [focused]")
                app.send(b"\x1b[F")  # End scrolls to the fingerprint.
                app.expect("Fingerprint (SHA-256)")
                app.send(b"f")
                app.expect("Fingerprint (SHA-1)")
                app.send(b"\x1b[H")  # Home restores the top fields.
                app.expect("Version: 3")
                app.resize(40, 8)
                app.expect("Resize terminal")
                app.resize(100, 30)
                app.expect("Certificate hierarchy", "Version: 3")
                app.send(b"\x1b")
                app.expect("root-cert", "Expires")
                app.send(b"\r")
                app.expect("Certificate hierarchy")
                app.send(exit_key)
                app.assert_restored(self)

    def test_quit_restores_terminal(self):
        self.exercise(b"q")

    def test_ctrl_c_restores_terminal(self):
        self.exercise(b"\x03")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=TerminalSmoke.binary)
    arguments = parser.parse_args()
    TerminalSmoke.binary = arguments.binary.resolve()
    unittest.main(argv=[sys.argv[0]], verbosity=2)
