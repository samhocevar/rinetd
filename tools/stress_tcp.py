#!/usr/bin/env python3
"""Local-only TCP forwarding load check. No production/service changes."""
import argparse
import json
import os
from pathlib import Path
import resource
import selectors
import socket
import subprocess
import tempfile
import threading
import time

HOST = '127.0.0.1'


def listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, 0))
    s.listen(2048)
    s.setblocking(False)
    return s


def echo_server(ls, stop, errors):
    sel = selectors.DefaultSelector()
    sel.register(ls, selectors.EVENT_READ)
    pending = {}
    try:
        while not stop.is_set():
            for key, mask in sel.select(0.1):
                if key.fileobj is ls:
                    try:
                        while True:
                            sock, _ = ls.accept()
                            sock.setblocking(False)
                            sel.register(sock, selectors.EVENT_READ)
                            pending[sock] = bytearray()
                    except BlockingIOError:
                        pass
                    continue
                sock = key.fileobj
                try:
                    if mask & selectors.EVENT_READ:
                        data = sock.recv(65536)
                        if not data:
                            sel.unregister(sock); pending.pop(sock, None); sock.close(); continue
                        pending[sock].extend(data)
                    if mask & selectors.EVENT_WRITE and pending[sock]:
                        sent = sock.send(pending[sock]); del pending[sock][:sent]
                    sel.modify(sock, selectors.EVENT_READ | (selectors.EVENT_WRITE if pending[sock] else 0))
                except (OSError, KeyError) as exc:
                    errors.append(str(exc))
                    try: sel.unregister(sock)
                    except Exception: pass
                    pending.pop(sock, None); sock.close()
    finally:
        for key in list(sel.get_map().values()):
            try: sel.unregister(key.fileobj); key.fileobj.close()
            except OSError: pass
        sel.close()


def proc_stats(pid):
    base = Path('/proc') / str(pid)
    try:
        mem = (base / 'status').read_text()
        rss = next((int(row.split()[1]) for row in mem.splitlines() if row.startswith('VmRSS:')), 0)
        return {'rss_kib': rss, 'fds': len(list((base / 'fd').iterdir()))}
    except (OSError, StopIteration):
        return {'rss_kib': None, 'fds': None}


def run_stage(n, proxy, process, hold, timeout):
    clients = []
    connected = 0
    verified = 0
    failures = []
    latency_ms = []
    peak = {'rss_kib': 0, 'fds': 0}
    try:
        for i in range(n):
            try:
                c = socket.create_connection((HOST, proxy), timeout=timeout)
                c.settimeout(timeout)
                clients.append(c)
                connected += 1
            except OSError as exc:
                failures.append(f'connect {i}: {exc}')
        # Verify bidirectional data with all connections held open.
        payloads = []
        for i, c in enumerate(clients):
            msg = f'rinetd-ng/stress/{n}/{i}'.encode()
            t0 = time.monotonic()
            try:
                c.sendall(msg)
                data = bytearray()
                while len(data) < len(msg):
                    part = c.recv(len(msg) - len(data))
                    if not part: break
                    data.extend(part)
                if data == msg:
                    verified += 1
                    latency_ms.append(round((time.monotonic() - t0) * 1000, 3))
                else: failures.append(f'echo {i}: mismatch or EOF')
            except OSError as exc:
                failures.append(f'echo {i}: {exc}')
        finish = time.monotonic() + hold
        while time.monotonic() < finish:
            stat = proc_stats(process.pid)
            for k in peak:
                if stat[k] is not None: peak[k] = max(peak[k], stat[k])
            if process.poll() is not None:
                failures.append(f'proxy exited: {process.returncode}'); break
            time.sleep(min(0.2, max(0, finish - time.monotonic())))
        result = {'connections_requested': n, 'connected': connected, 'echo_verified': verified,
                  'errors': failures[:20], 'error_count': len(failures), 'peak_proxy': peak,
                  'echo_latency_ms': {'min': min(latency_ms) if latency_ms else None,
                                      'max': max(latency_ms) if latency_ms else None,
                                      'mean': round(sum(latency_ms) / len(latency_ms), 3) if latency_ms else None},
                  'passed': connected == n and verified == n and not failures}
        return result
    finally:
        for c in clients:
            try: c.close()
            except OSError: pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', default='./upstream/rinetd')
    ap.add_argument('--connections', nargs='+', type=int, default=[100, 250, 500])
    ap.add_argument('--hold', type=float, default=2)
    ap.add_argument('--timeout', type=float, default=2)
    ap.add_argument('--output', default='stress-results.json')
    a = ap.parse_args()
    if any(n < 1 or n > 2000 for n in a.connections) or not 0 <= a.hold <= 3600 or a.timeout <= 0:
        ap.error('connections must be 1..2000; hold 0..3600; timeout > 0')
    binary = Path(a.binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        ap.error(f'executable not found: {binary}; run ./install.sh --build-only')
    need = max(a.connections) * 3 + 128
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < need:
        print(f'Warning: open-file limit {soft} below suggested {need}; raise ulimit -n in the lab', flush=True)
    stop = threading.Event(); errors = []
    dest = listener()
    worker = threading.Thread(target=echo_server, args=(dest, stop, errors), daemon=True)
    worker.start()
    ingress = listener()
    proxy_port = ingress.getsockname()[1]
    ingress.close()
    with tempfile.TemporaryDirectory(prefix='rinetd-ng-stress-') as temp:
        conf = Path(temp) / 'rinetd.conf'
        conf.write_text(f'{HOST} {proxy_port}/tcp {HOST} {dest.getsockname()[1]}/tcp\nallow {HOST}\n')
        process = subprocess.Popen([str(binary), '-f', '-c', str(conf)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(0.25)
            if process.poll() is not None:
                raise RuntimeError(f'proxy exited during start: {process.communicate()[1]}')
            results = []
            for n in a.connections:
                row = run_stage(n, proxy_port, process, a.hold, a.timeout)
                results.append(row)
                print(json.dumps(row, ensure_ascii=False), flush=True)
                if not row['passed']: break
            report = {'binary': str(binary), 'stages': results, 'server_errors': errors[:20],
                      'passed': bool(results) and len(results) == len(a.connections)
                      and all(x['passed'] for x in results) and not errors}
            Path(a.output).write_text(json.dumps(report, indent=2) + '\n')
            print(f'Report: {Path(a.output).resolve()}')
            return 0 if report['passed'] else 1
        finally:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            stop.set(); worker.join(timeout=2)


if __name__ == '__main__':
    raise SystemExit(main())
