"""Local dev server for the demo site.

Serves site/dist/ over the LAN so you can open it on a phone and point a real
SeedSigner at the screen — which is the only way to actually test this. Prints
every address it's reachable on.

Run:  python -m tools.serve            (port 8000)
      python -m tools.serve 8080
"""
import http.server
import os
import socket
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "site", "dist")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIST, **kwargs)

    def end_headers(self):
        # The build output is regenerated constantly during development; a
        # cached index.json is the most confusing possible failure mode.
        self.send_header("Cache-Control", "no-store, must-revalidate")
        super().end_headers()

    def log_message(self, fmt, *args):
        if "404" in (fmt % args):
            sys.stderr.write("  404 %s\n" % (fmt % args))


def local_addresses() -> list:
    addrs = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))       # no packets sent; just picks a route
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith("127."))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

    if not os.path.isdir(DIST):
        sys.exit(f"{DIST} does not exist — run `python -m tools.build_site` first.")

    try:
        server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    except OSError as e:
        # Silently losing the bind and then browsing whatever *else* is on the
        # port is a genuinely baffling way to waste ten minutes.
        sys.exit(f"Could not bind port {port}: {e}\n"
                 f"Something else is already listening there. "
                 f"Try `python -m tools.serve {port + 1}`.")

    print(f"Serving {DIST}\n")
    print(f"  this machine : http://localhost:{port}/")
    for addr in local_addresses():
        print(f"  on your LAN  : http://{addr}:{port}/")
    print("\nOpen the LAN address on a phone to test with real hardware. Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
