#!/usr/bin/env python3
"""Exercise the built TUI in a real Unix PTY using generated public test data.

Run `cargo build --locked`, then `python3 tests/terminal_smoke.py`.
Requires Python 3 and a Unix terminal API (including Linux/WSL); no pip packages.
"""

import argparse
import base64
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
                app.expect("Certificate hierarchy", "Version: 3", "[verified]")
                app.send(b"\t")
                app.expect("Certificate details [focused]")
                app.send(b"\x1b[F")  # End scrolls to the fingerprint and extensions.
                app.expect(
                    "Signature: verified with its own public key (self-signed).",
                    "Fingerprint (SHA-256)",
                    "Extensions:",
                    "Subject Key Identifier (2.5.29.14)",
                )
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

    def triage(self, quit_while_typing, exit_key):
        with tempfile.TemporaryDirectory(prefix="terminal-check-", dir=ROOT / "target") as directory:
            Path(directory, "triage.jks").write_bytes(triage_keystore())
            with PtyApp(self.binary, directory) as app:
                app.expect("No keystore selected")
                app.send(b"o")
                app.expect("triage.jks")
                app.send(b"\x1b[B")  # Skip the parent-directory row.
                app.send(b"\r")
                app.expect("alpha", "beta-quit", "zeta-soon", "3 entries | Sort: alias")
                app.send(b"/")
                app.expect("Type to filter", "Filter: _ | 3 of 3 entries")
                app.send(b"q")  # Typed into the filter, not a quit.
                app.expect("Filter: q_ | 1 of 3 entries", "beta-quit")
                self.assertIsNone(app.process.poll())
                self.assertNotIn("alpha", app.screen())
                app.send(b"x")
                app.expect("Filter: qx_ | 0 of 3 entries", "No matching entries")
                app.send(b"\x1b")  # Cancels and clears the filter.
                app.expect("3 entries | Sort: alias", "alpha", "Up/Down j/k Scroll")
                self.assertNotIn("Filter:", app.screen())
                app.send(b"/zeta\r")
                app.expect("Filter: 'zeta' | 1 of 3 entries")
                self.assertNotIn("alpha", app.screen())
                app.send(b"\r")  # Details open for the filtered selection.
                app.expect("Certificate hierarchy", "zeta-soon")
                app.send(b"\x1b")
                app.expect("Filter: 'zeta' | 1 of 3 entries")
                app.send(b"/")
                app.expect("Filter: zeta_")
                app.send(b"\x1b")
                app.expect("3 entries | Sort: alias", "alpha")
                screen = app.screen()
                self.assertLess(screen.index("alpha"), screen.index("zeta-soon"))
                app.send(b"s")
                app.expect("3 entries | Sort: expiry")
                screen = app.screen()
                self.assertLess(screen.index("zeta-soon"), screen.index("alpha"))
                app.send(b"s")
                app.expect("3 entries | Sort: alias")
                app.send(b"/a\r")
                app.expect("Filter: 'a' | 3 of 3 entries")
                if quit_while_typing:
                    app.send(b"/")
                    app.expect("Filter: a_")
                app.send(exit_key)
                app.assert_restored(self)

    def test_filter_and_sort_then_quit_restores_terminal(self):
        self.triage(False, b"q")

    def test_filter_and_sort_then_escape_restores_terminal(self):
        self.triage(False, b"\x1b")

    def test_ctrl_c_while_filtering_restores_terminal(self):
        self.triage(True, b"\x03")

    def certificate_file(self, exit_key):
        der = fixture_certificate()
        pem = certificate_pem(der)
        with tempfile.TemporaryDirectory(prefix="terminal-check-", dir=ROOT / "target") as directory:
            Path(directory, "bundle.pem").write_text(pem)
            with PtyApp(self.binary, directory) as app:
                app.expect("No keystore selected")
                app.send(b"o")
                app.expect("bundle.pem")
                app.send(b"\x1b[B")  # Skip the parent-directory row.
                app.send(b"\r")
                app.expect("JKS TUI test fixture", "Certificate", "1 entries | Sort: alias")
                app.send(b"\r")
                app.expect("Certificate hierarchy", "x Export certificate")
                app.send(b"x")
                app.expect("Save certificate to:")
                app.send(b"\x15")  # Ctrl+U clears the suggested absolute path.
                app.expect("Save certificate to: _")
                app.send(b"q")  # Typed into the name, not a quit.
                app.expect("Save certificate to: q_")
                self.assertIsNone(app.process.poll())
                app.send(b"x\x7f.pem\r")  # Backspace, then save next to the file.
                app.expect("Saved certificate to")
                saved = Path(directory, "q.pem")
                self.assertEqual(saved.read_text(), pem)
                app.send(b"X")
                app.expect("Save chain to:")
                app.send(b"\x1b")  # Cancels the export, staying in the details.
                app.expect("x Export certificate", "Certificate hierarchy")
                app.send(exit_key)
                app.assert_restored(self)

    def requests_and_revocation_lists(self, exit_key):
        fixtures = ROOT / "tests/fixtures"
        with tempfile.TemporaryDirectory(prefix="terminal-check-", dir=ROOT / "target") as directory:
            # The PEM bundle holds the CA certificate, then the list it signed.
            Path(directory, "a-list.crl").write_bytes((fixtures / "openssl-ca-crl.pem").read_bytes())
            Path(directory, "b-request.csr").write_bytes((fixtures / "openssl-request.csr").read_bytes())
            with PtyApp(self.binary, directory) as app:
                app.expect("No keystore selected", ".csr, .p10", ".crl")
                app.send(b"o")
                app.expect("a-list.crl", "b-request.csr")
                app.send(b"\x1b[B\r")  # Skip the parent-directory row and open the list.
                app.expect("Revocation list", "2 entries | Sort: alias")
                app.send(b"\x1b[B\r")
                app.expect("Revocation list: CN=keystore-tui test CA [verified]")
                app.send(b"\t\x1b[F")  # Focus the details and scroll to the end.
                app.expect(
                    "CRL Number (2.5.29.20)",
                    "Revoked Certificates: 1",
                    "Serial Number: 0x0A (10)",
                    "Key Compromise",
                )
                app.send(b"\x1b")
                app.expect("2 entries | Sort: alias")
                app.send(b"o")
                app.expect("b-request.csr")
                app.send(b"\x1b[B\x1b[B\r")
                app.expect("keystore-tui test request", "Certificate request", "RSA", "2048 bits")
                app.send(b"\r")
                app.expect(
                    "Request: CN=keystore-tui test request [verified]",
                    "Signature: verified with its own public key (proof of possession).",
                )
                app.send(exit_key)
                app.assert_restored(self)

    def test_requests_and_revocation_lists_then_quit_restores_terminal(self):
        self.requests_and_revocation_lists(b"q")

    def test_requests_and_revocation_lists_then_ctrl_c_restores_terminal(self):
        self.requests_and_revocation_lists(b"\x03")

    def test_certificate_file_export_then_quit_restores_terminal(self):
        self.certificate_file(b"q")

    def test_certificate_file_export_then_ctrl_c_restores_terminal(self):
        self.certificate_file(b"\x03")


def fixture_certificate():
    """The DER certificate stored in the public fixture under `root-cert`."""
    data = (ROOT / "tests/fixtures/trusted-cert.jks").read_bytes()
    offset = 12 + 4 + 2 + len(b"root-cert") + 8 + 2 + len(b"X.509")
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    return data[offset + 4 : offset + 4 + length]


def certificate_pem(der):
    body = base64.b64encode(der).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"

def triage_keystore():
    """Build an empty-password JKS with three copies of the public fixture
    certificate. One copy's notAfter is moved earlier to exercise sorting;
    certificate signatures are never checked by the app."""
    certificate = fixture_certificate()
    not_after = b"361009194829Z"
    assert certificate.count(not_after) == 1, "unexpected fixture expiry"
    earlier = certificate.replace(not_after, b"301009194829Z")

    def utf(text):
        encoded = text.encode()
        return struct.pack(">H", len(encoded)) + encoded

    entries = [("alpha", certificate), ("beta-quit", certificate), ("zeta-soon", earlier)]
    body = struct.pack(">III", 0xFEEDFEED, 2, len(entries))
    for alias, der in entries:
        body += struct.pack(">I", 2) + utf(alias) + struct.pack(">Q", 0)
        body += utf("X.509") + struct.pack(">I", len(der)) + der
    return body + hashlib.sha1(b"Mighty Aphrodite" + body).digest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=TerminalSmoke.binary)
    arguments = parser.parse_args()
    TerminalSmoke.binary = arguments.binary.resolve()
    unittest.main(argv=[sys.argv[0]], verbosity=2)
