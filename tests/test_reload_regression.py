"""Opt-in live reload regression tests. Run with RINETD_RUN_RELOAD_TESTS=1.

These tests expose known upstream failures, not a claim that reload is fixed.
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
pytestmark = [
    pytest.mark.skipif(not BIN.is_file(), reason='compiled rinetd binary required'),
    pytest.mark.skipif(os.environ.get('RINETD_RUN_RELOAD_TESTS') != '1',
                       reason='opt in using RINETD_RUN_RELOAD_TESTS=1'),
]


def free_port(socktype):
    with socket.socket(socket.AF_INET, socktype) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def test_repeated_udp_reload(tmp_path):
    count = int(os.environ.get('RINETD_RELOAD_CYCLES', '100'))
    assert 1 <= count <= 1000
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(('127.0.0.1', 0))
    upstream.settimeout(.2)
    port = free_port(socket.SOCK_DGRAM)
    cfg = tmp_path / 'rinetd.conf'
    cfg.write_text(f'127.0.0.1 {port}/udp 127.0.0.1 {upstream.getsockname()[1]}/udp\nallow 127.0.0.1\n')
    finished = threading.Event()

    def echo():
        while not finished.is_set():
            try:
                data, peer = upstream.recvfrom(4096)
                if data:  # upstream sends an initial zero-length UDP datagram
                    upstream.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    worker = threading.Thread(target=echo, daemon=True)
    worker.start()
    process = subprocess.Popen([str(BIN), '-f', '-c', str(cfg)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(.2)
        assert process.poll() is None, 'rinetd failed to start'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1.5)
            for i in range(count):
                if i:
                    process.send_signal(signal.SIGHUP)
                    time.sleep(.025)
                assert process.poll() is None, f'rinetd exited after reload {i}'
                payload = f'reload-{i}'.encode()
                # UDP is best-effort: retries reduce timing-induced failures.
                for attempt in range(3):
                    client.sendto(payload, ('127.0.0.1', port))
                    try:
                        data, _ = client.recvfrom(4096)
                        if data == payload:
                            break
                    except socket.timeout:
                        pass
                else:
                    pytest.fail(f'UDP echo lost after reload {i}')
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        finished.set()
        upstream.close()
        worker.join(timeout=2)
