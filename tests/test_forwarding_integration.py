"""End-to-end tests against actual compiled rinetd (safe localhost sockets only).
Run after tools/build.sh; tests skip if the binary is unavailable.
"""
import os
import pathlib
import socket
import subprocess
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path(os.environ.get('RINETD_TEST_BIN', str(ROOT / 'upstream' / 'rinetd')))
pytestmark = pytest.mark.skipif(not BIN.is_file(), reason='compile upstream/rinetd first')


def port(kind):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def launch(tmp_path, proto, listen_port, target_port):
    suffix = '/udp' if proto == 'udp' else ''
    cfg = tmp_path / 'rinetd.conf'
    cfg.write_text(f'127.0.0.1 {listen_port}{suffix} 127.0.0.1 {target_port}{suffix}\nallow 127.0.0.1\n')
    p = subprocess.Popen([str(BIN), '-f', '-c', str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(.3)
    if p.poll() is not None:
        raise AssertionError(f'rinetd exited prematurely: {p.stderr.read().decode(errors="replace")}')
    return p


def stop(p):
    p.terminate()
    try:
        p.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate(timeout=3)


def test_tcp_forward_echo(tmp_path):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(3)
    target = listener.getsockname()[1]
    proxy = port(socket.SOCK_STREAM)
    errors = []

    def server():
        try:
            with listener:
                conn, _ = listener.accept()
                with conn:
                    data = conn.recv(4096)
                    conn.sendall(data)
        except Exception as exc:
            errors.append(exc)

    th = threading.Thread(target=server, daemon=True)
    th.start()
    p = launch(tmp_path, 'tcp', proxy, target)
    try:
        with socket.create_connection(('127.0.0.1', proxy), timeout=2) as c:
            c.settimeout(3)
            c.sendall(b'rinetd-ng TCP echo')
            assert c.recv(4096) == b'rinetd-ng TCP echo'
        th.join(timeout=4)
        assert not errors
    finally:
        stop(p)
        listener.close()


def test_udp_forward_echo(tmp_path):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('127.0.0.1', 0))
    server_sock.settimeout(5)
    target = server_sock.getsockname()[1]
    proxy = port(socket.SOCK_DGRAM)
    errors = []

    def server():
        try:
            with server_sock:
                # Upstream rinetd sends an empty UDP datagram when creating
                # its outbound socket. Ignore that probe; echo user payload.
                while True:
                    data, peer = server_sock.recvfrom(4096)
                    if data:
                        server_sock.sendto(data, peer)
                        break
        except Exception as exc:
            errors.append(exc)

    th = threading.Thread(target=server, daemon=True)
    th.start()
    p = launch(tmp_path, 'udp', proxy, target)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            c.settimeout(5)
            c.sendto(b'rinetd-ng UDP echo', ('127.0.0.1', proxy))
            data, _ = c.recvfrom(4096)
            assert data == b'rinetd-ng UDP echo'
        th.join(timeout=4)
        assert not errors
    finally:
        stop(p)
        server_sock.close()
