# TCP load test (local-only)

Run `./install.sh --test-stress` after `./install.sh --build-only`.
The test creates a separate rinetd process and echo server bound to `127.0.0.1`; it does not modify the installed service or `/etc/rinetd.conf`.
It exercises 100, 250 and 500 simultaneous TCP clients (configurable using the Python CLI), sends and checks echoed payloads, and outputs JSON with peak RSS, FDs, latency, and errors.

Examples:

```bash
python3 tools/stress_tcp.py --binary ./upstream/rinetd --connections 100 250 500 --hold 3
python3 tools/stress_tcp.py --binary ./upstream/rinetd --connections 1000 --hold 5 --output /tmp/stress-1000.json
```

This is a short functional load test, **not** a 30-minute soak test, vulnerability scan, or proof of production capacity. Run on lab machines: 500 concurrent clients can consume more than 1500 file descriptors in the test process and server. The stress tool does not send traffic to outside hosts.
