TVtunX v2.0.1 downloads
-----------------------
What's new in 2.0: DUAL-STACK carrier. Every transport (reality-udp / udp /
browser) now listens on the SAME port over BOTH UDP and TCP. The relay uses UDP
when it can and automatically falls back to TCP if UDP is blocked, so a firewall
or ISP that drops UDP no longer stops the tunnel. No server-side change needed.

Easiest install (needs only git, no Go):
    git clone https://github.com/hamid8989/tvtunx.git
    cd tvtunx && sudo bash deploy/install.sh

Direct binary (x86_64 / most VPS incl. Hetzner):
    https://github.com/hamid8989/tvtunx/raw/main/dist/tvtunx-linux-amd64
Full source tarball:
    https://github.com/hamid8989/tvtunx/raw/main/release/tvtunx-2.0.1.tar.gz
Verify: sha256sum -c SHA256SUMS.txt   (from repo root)

After install, open the tunnel port for BOTH udp and tcp (incl. any cloud
firewall, e.g. Hetzner). If UDP is blocked the tunnel still works over TCP.
