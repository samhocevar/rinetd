#!/usr/bin/env python3
"""Local TCP longevity / destination-failure test. Never touches installed service."""
import argparse, json, os, resource, socket, subprocess, tempfile, threading, time, pathlib, sys

def tcp_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--binary',default='./upstream/rinetd')
    a.add_argument('--connections',type=int,default=50)
    a.add_argument('--duration',type=float,default=60)
    a.add_argument('--interval',type=float,default=1)
    a.add_argument('--output',default='resilience-results.json')
    args=a.parse_args()
    if not (1<=args.connections<=2000 and 1<=args.duration<=3600 and .05<=args.interval<=120): a.error('outside safe lab limits')
    binpath=pathlib.Path(args.binary).resolve()
    if not binpath.is_file(): a.error('binary missing')
    if resource.getrlimit(resource.RLIMIT_NOFILE)[0]<args.connections*2+128: a.error('increase ulimit -n for lab')
    target=tcp_port(); front=tcp_port(); halt=threading.Event(); errors=[]; received=0; lock=threading.Lock()
    listener=socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); listener.bind(('127.0.0.1',target)); listener.listen(args.connections+32); listener.settimeout(.2)
    peers=[]
    def serve(conn):
        nonlocal received
        with conn:
            conn.settimeout(.5)
            while not halt.is_set():
                try:
                    data=conn.recv(4096)
                    if not data: break
                    conn.sendall(data)
                    with lock: received+=1
                except socket.timeout: continue
                except OSError: break
    def acceptor():
        while not halt.is_set():
            try:
                c,_=listener.accept(); t=threading.Thread(target=serve,args=(c,),daemon=True); t.start(); peers.append(t)
            except socket.timeout: continue
            except OSError: break
    threading.Thread(target=acceptor,daemon=True).start()
    report={'connections_requested':args.connections,'duration_seconds':args.duration,'round_trips':0,'failures':[],'proxy_exit':None}
    with tempfile.TemporaryDirectory(prefix='rinetd-resilience-') as tmp:
        cfg=pathlib.Path(tmp)/'rinetd.conf'; cfg.write_text(f'127.0.0.1 {front}/tcp 127.0.0.1 {target}/tcp\nallow 127.0.0.1\n')
        proc=subprocess.Popen([str(binpath),'-f','-c',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        clients=[]
        try:
            time.sleep(.3)
            if proc.poll() is not None: raise RuntimeError('proxy exited at startup')
            for i in range(args.connections):
                c=socket.create_connection(('127.0.0.1',front),timeout=4); c.settimeout(3); clients.append(c)
            deadline=time.monotonic()+args.duration; round_id=0
            while time.monotonic()<deadline:
                if proc.poll() is not None: raise RuntimeError('proxy unexpectedly exited')
                for i,c in enumerate(clients):
                    data=f'{round_id}:{i}'.encode(); c.sendall(data); got=bytearray()
                    while len(got)<len(data):
                        part=c.recv(len(data)-len(got))
                        if not part: raise RuntimeError(f'EOF on client {i}')
                        got.extend(part)
                    if got!=data: raise RuntimeError(f'mismatched echo on client {i}')
                    report['round_trips']+=1
                round_id+=1
                time.sleep(args.interval)
        except Exception as exc:
            report['failures'].append(str(exc))
        finally:
            for c in clients: c.close()
            halt.set(); listener.close()
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            report['proxy_exit']=proc.returncode
            report['accepted_connections']=len(peers)
    report['passed']=not report['failures'] and report['round_trips']>=args.connections and report['accepted_connections']>=args.connections
    pathlib.Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
