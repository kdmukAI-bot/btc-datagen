"""Local dev server for the demo site.

Serves site/dist/ over the LAN so you can open it on a phone and point a real
SeedSigner at the screen — which is the only way to actually test this. Prints
every address it's reachable on.

Run:  python -m tools.serve            (port 8000)
      python -m tools.serve 8080
      python -m tools.serve --tls      (https, for testing the camera step)

--tls exists because of the secure-context rule: `navigator.mediaDevices` is
undefined on a plain http:// page unless the host is localhost, so the
scan-the-signature-back step cannot open a camera when a phone reaches the dev
server by LAN IP. The certificate is self-signed and generated on the spot with
the machine's own addresses as SANs.
"""
import argparse
import http.server
import os
import shutil
import socket
import ssl
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "site", "dist")
CERT_DIR = os.path.join(ROOT, ".devcert")
CERT = os.path.join(CERT_DIR, "cert.pem")
KEY = os.path.join(CERT_DIR, "key.pem")
SAN_STAMP = os.path.join(CERT_DIR, "san.txt")


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


# Python's mimetypes reads /etc/mime.types, and .wasm is missing from it on
# plenty of distributions. Serving the module as application/octet-stream makes
# the browser refuse it — `WebAssembly.instantiateStreaming` requires the exact
# type — with an error that reads like a corrupt file rather than a MIME
# problem. GitHub Pages gets this right; the dev server has to be told.
Handler.extensions_map = dict(Handler.extensions_map)
Handler.extensions_map[".wasm"] = "application/wasm"
Handler.extensions_map[".mjs"] = "text/javascript"


# Interfaces whose addresses are never useful to browse to: container bridges
# and virtual ethernet pairs. Everything else — including tailscale0 — is fair
# game, because "open it on the phone" increasingly means over a tailnet rather
# than the local subnet, and an address missing from the certificate's SANs is
# rejected by Chrome with no click-through offered.
SKIP_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr")


def local_addresses() -> list:
    """Every IPv4 address a browser could plausibly reach this server on.

    The old version asked the routing table for the address used to reach the
    internet and looked up the hostname, which finds the primary LAN address and
    nothing else — no Tailscale, no second NIC. That is fine for printing a URL
    and quietly wrong for generating a certificate.
    """
    addrs = set()

    # Linux: enumerate for real. `ip` is in the base system on any distribution
    # that has systemd, which is where this gets run.
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                             capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            iface, cidr = fields[1], fields[3]
            if iface.startswith(SKIP_IFACE_PREFIXES):
                continue
            addrs.add(cidr.split("/")[0])
    except (OSError, subprocess.CalledProcessError):
        pass

    if not addrs:                              # non-Linux, or no `ip`
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))   # no packets sent; just picks a route
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


def address_label(addr: str) -> str:
    # Tailscale hands out addresses from the 100.64.0.0/10 shared-address block.
    if addr.startswith("100.") and 64 <= int(addr.split(".")[1]) <= 127:
        return "tailnet"
    return "LAN"


def ensure_cert(addresses: list) -> None:
    """Self-signed certificate covering localhost and every LAN address.

    Regenerated whenever the address set changes: a certificate whose SANs no
    longer include the IP you are browsing to is rejected outright by Chrome,
    with no click-through, and "it worked yesterday" after a DHCP lease change
    is a miserable thing to debug.
    """
    san = ",".join(["DNS:localhost", "IP:127.0.0.1"]
                   + [f"IP:{a}" for a in addresses])

    if os.path.exists(CERT) and os.path.exists(KEY) and os.path.exists(SAN_STAMP):
        with open(SAN_STAMP) as f:
            if f.read().strip() == san:
                return

    if not shutil.which("openssl"):
        sys.exit("--tls needs the `openssl` command, which is not on PATH.")

    os.makedirs(CERT_DIR, exist_ok=True)
    print(f"Generating a self-signed certificate for {san}")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", KEY, "-out", CERT, "-days", "825",
         "-subj", "/CN=btc-datagen dev server",
         "-addext", f"subjectAltName={san}"],
        check=True, capture_output=True,
    )
    with open(SAN_STAMP, "w") as f:
        f.write(san)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", nargs="?", type=int, default=None,
                    help="default 8000, or 8443 with --tls")
    ap.add_argument("--tls", action="store_true",
                    help="serve https with a self-signed certificate, so the "
                         "camera step works from a phone on the LAN")
    args = ap.parse_args()

    port = args.port if args.port is not None else (8443 if args.tls else 8000)
    scheme = "https" if args.tls else "http"

    if not os.path.isdir(DIST):
        sys.exit(f"{DIST} does not exist — run `python -m tools.build_site` first.")

    addresses = local_addresses()
    if args.tls:
        ensure_cert(addresses)

    try:
        server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    except OSError as e:
        # Silently losing the bind and then browsing whatever *else* is on the
        # port is a genuinely baffling way to waste ten minutes.
        sys.exit(f"Could not bind port {port}: {e}\n"
                 f"Something else is already listening there. "
                 f"Try `python -m tools.serve {port + 1}`.")

    if args.tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT, KEY)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"Serving {DIST}\n")
    print(f"  this machine : {scheme}://localhost:{port}/")
    for addr in addresses:
        print(f"  on your {address_label(addr):<7s}: {scheme}://{addr}:{port}/")

    if args.tls:
        print("\nThe certificate is self-signed, so every browser will warn once.")
        print("  Android/Chrome : tap Advanced -> Proceed. Camera works after that.")
        print("  iOS/Safari     : Safari will NOT grant camera access to an untrusted")
        print("                   certificate, however many times you click through.")
        print(f"                   Install {CERT} via Settings -> General -> VPN &")
        print("                   Device Management, then turn it on under About ->")
        print("                   Certificate Trust Settings.")
        print("\nNo certificate at all, if you have adb: `adb reverse tcp:%d tcp:%d`,"
              % (port, port))
        print("  then open http://localhost:%d/ on the phone — localhost is a secure" % port)
        print("  context by definition, so the camera works over plain http.")
    else:
        print("\nOpen the LAN address on a phone to test with real hardware.")
        print("The camera step (reading the signature back) needs --tls: browsers")
        print("refuse getUserMedia on an insecure origin unless it is localhost.")
    print("\nCtrl-C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
