"""Live reload acceptance tests; deliberately exercise a *changed* target.

Use RINETD_RUN_RELOAD_TESTS=1 and a compiled upstream/rinetd.
"""
import os
import pathlib
import signal
import socket
import subprocess
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path(os.environ.get('RINETD_TEST_BIN', str(ROOT / 'upstream/rinetd')))
pytestmark = [pytest.mark.skipif(not BIN.is_file(), reason='compiled rinetd required'),
              pytest.mark.skipif(os.environ.get('RINETD_RUN_RELOAD_TESTS') != '1', reason='opt-in live reload test')]


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class UDPEcho:
    def __init__(self, prefix):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(.1)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.prefix = prefix
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        while not self.stop_event.is_set():
            try:
                message, peer = self.sock.recvfrom(4096)
                if message:  # rinetd sends a zero-sized UDP probe at session start
                    self.sock.sendto(self.prefix + message, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self.stop_event.set()
        self.sock.close()
        self.worker.join(timeout=2)


def write_rule(path, port, target):
    path.write_text(f'127.0.0.1 {port}/udp 127.0.0.1 {target}/udp\nallow 127.0.0.1\n')


def query(sock, port, payload, expected, timeout=4):
    deadline = time.monotonic() + timeout
    sock.settimeout(.15)
    while time.monotonic() < deadline:
        sock.sendto(payload, ('127.0.0.1', port))
        try:
            answer, _ = sock.recvfrom(4096)
            if answer == expected:
                return True
        except socket.timeout:
            pass
    return False


def test_reload_switches_udp_destination(tmp_path):
    a, b = UDPEcho(b'A:'), UDPEcho(b'B:')
    port = free_port(socket.SOCK_DGRAM)
    cfg = tmp_path / 'rinetd.conf'
    write_rule(cfg, port, a.port)
    proc = subprocess.Popen([str(BIN), '-f', '-c', str(cfg)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(.25)
        assert proc.poll() is None, 'rinetd exited on startup'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            assert query(client, port, b'one', b'A:one'), 'initial destination failed'
            write_rule(cfg, port, b.port)
            proc.send_signal(signal.SIGHUP)
            assert query(client, port, b'two', b'B:two'), 'destination did not switch after SIGHUP'
            assert proc.poll() is None, 'rinetd exited during reload'
    finally:
        proc.terminate()
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.communicate(timeout=3)
        a.stop(); b.stop()
