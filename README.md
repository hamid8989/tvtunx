# TVtunX — a DPI-resistant, loss-tolerant TCP+UDP tunnel
# TVtunX — تونل TCP+UDP مقاوم در برابر DPI و افت/throttle

A from-scratch **raw port-forwarding** tunnel core in Go — one static binary. The
`udp` and `reality-udp` transports are **pure Go standard library, zero external
dependencies**; the optional `browser` transport adds one library (`quic-go`) for
real HTTP/3. It forwards whole TCP and UDP ports between a **relay** (inner/
restricted side) and an **exit** (abroad), without inspecting or terminating any
application protocol.
Whatever your client speaks to the relay port — VLESS, VMess, Trojan, Reality,
WireGuard, plain TCP/UDP — is carried verbatim to the destination behind the exit.

یک هسته‌ی تونل **port-forward خام**، نوشته‌شده با **کتابخانه‌ی استانداردِ Go و بدون
هیچ وابستگیِ بیرونی** — یک باینریِ استاتیکِ کوچک. یک پورتِ کاملِ TCP و UDP را بین
**رله** (داخل) و **خروجی** (خارج) فوروارد می‌کند، بدون دست‌زدن به محتوای پروتکل.
هر کانفیگی (VLESS/VMess/Reality/WireGuard/…) روی آن سوار می‌شود.

---

## Why a UDP carrier? / چرا حاملِ UDP؟

A tunnel that carries your (already-TCP) traffic over an **outer TCP** connection
suffers **TCP-over-TCP meltdown**: on a lossy or throttled link the two
retransmission layers fight each other and throughput collapses. TVtunX carries
everything over a **reliable-UDP** layer (`internal/rudp`) instead: there is no
outer TCP, loss is recovered by selective retransmission, and the send rate does
**not** collapse on loss — the behaviour that stays fast when an ISP throttles or
the path is lossy.

تونلی که ترافیکِ (ذاتاً TCP) شما را روی یک **TCP بیرونی** حمل کند دچارِ پدیده‌ی
**TCP-over-TCP meltdown** می‌شود و روی مسیرِ پرافت/throttle سرعت فرومی‌پاشد. TVtunX
همه‌چیز را روی یک لایه‌ی **UDP قابل‌اطمینان** حمل می‌کند؛ TCP بیرونی وجود ندارد،
افت با ارسالِ مجددِ انتخابی جبران می‌شود و نرخ روی افت فرونمی‌پاشد.

**Brutal congestion control (Hysteria-style).** For `udp` and `reality-udp`, set a
speed target (`-udp-target 50`, i.e. ~50 Mbit): the sender holds that rate through
packet loss — on loss it sends *faster* (by 1/delivered-fraction) and sizes its
window to the bandwidth-delay product, instead of backing off like TCP. This is
what keeps throughput up on a throttled, lossy link. 0 = adaptive/unpaced.
(`browser` uses QUIC's own congestion control.)

---

## Transports / ترانسپورت‌ها

Pick one with `-transport` (the **same on both ends**):

| transport | what it looks like on the wire | when to use |
|-----------|-------------------------------|-------------|
| `reality-udp` | a real **QUIC v1 / HTTP-3** handshake to an allowed site (Chrome-shaped ClientHello, real SNI) | **default** — best against DPI that classifies UDP, no extra setup |
| `udp` | obfuscated UDP, not disguised as a named protocol | fastest / lowest overhead, for links that only throttle UDP |
| `browser` | a **genuine HTTP/3 visit to a real website** on your domain, with a real Let's Encrypt certificate | **strongest realism** — not imitation, it IS browser traffic; needs a domain |

### Dual-stack: automatic TCP fallback / حالتِ دو-لایه و fallback خودکار به TCP

Every transport is **dual-stack**. The exit listens on the **same port over both
UDP and TCP**, and the relay picks the network automatically (`-net auto`, the
default): it races the UDP carrier and a TCP carrier and keeps whichever connects
first, remembering it for later sessions. So a firewall or ISP that **blocks or
drops UDP** — the common case in some networks — no longer stops the tunnel: it
transparently continues over TCP. The TCP carrier is a normal **TLS (HTTPS-looking)
connection** authenticated by the same PSK (a short HMAC knock after the TLS
handshake; the certificate is not trusted on its own), so on the wire it looks like
an ordinary web connection to the transport's site/domain.

Force a single network with `-net udp` or `-net tcp` when you already know the path.
No server-side change is ever needed — the exit always serves both.

هر ترانسپورت **دو-لایه** است: خروجی روی **همان پورت، هم UDP و هم TCP** گوش می‌دهد و
رله خودکار (`-net auto`) هر کدام که وصل شود را انتخاب می‌کند. بنابراین اگر فایروال یا
ISP فقط **UDP را ببندد**، تونل به‌طور شفاف روی **TCP** بالا می‌آید و قطع نمی‌شود. لایه‌ی
TCP یک اتصالِ **TLS (شبیهِ HTTPS)** است که با همان PSK احراز می‌شود.

### `browser` — a real website, not an imitation

The exit hosts a **real website** on a domain you own, with a **real Let's Encrypt
certificate it fetches automatically**, served over **HTTP/3 (QUIC/UDP)**. The relay
connects to it exactly the way a browser does — a real H3 request, verifying the
real certificate — and the tunnel rides inside that request's duplex stream. Any
other visitor (a prober, a scanner) just gets a small ordinary web page. Because the
destination is a real site with a valid cert and the handshake is real H3, there is
nothing to tell apart from normal web browsing — it isn't mimicry, it is the real
thing. It keeps the UDP/loss-tolerance of the other transports (H3 is over QUIC).

Setup is one DNS record. The installer walks you through it:

```
Enter a domain you own (e.g. cdn.example.com): cdn.example.com

Create ONE DNS record at your domain provider, then press Enter:
    Type:  A
    Name:  cdn.example.com
    Value: 203.0.113.9        (this exit server's IP)
    Proxy: OFF  (grey cloud / "DNS only" — NOT orange)
```

The exit needs **:80/tcp** open (for the one-time certificate check) and the tunnel
UDP port open. The certificate is obtained automatically on the first connection —
you never touch certbot. Use the **same domain** on the relay.

**Certificate when :80 is taken (DNS-01).** If another service already uses port 80
(e.g. a panel node's xray), the installer switches to the **DNS-01** method, which
needs **no open port** — it validates via a DNS TXT record and issues a **wildcard**
cert for `*.t.yourdomain.com`. Two ways:
- **Cloudflare API** — paste a token (`Zone:DNS:Edit`) and it's fully automatic,
  including renewals (`-cf-token`).
- **Manual** — the tool prints one TXT record for you to add; renew by re-running
  `tvtunx cert` (about every 60 days).
Run it directly any time with:
```sh
tvtunx cert -domain yourdomain.com -label t -dns cloudflare -cf-token <TOKEN>
# or: tvtunx cert -domain yourdomain.com -label t -dns manual
```

**Rotating subdomains (defeat SNI blocklists).** With a wildcard label (the
installer's default), both ends derive a fresh hostname **per day** from the PSK
under `*.t.yourdomain.com` — e.g. `047c6275.t.yourdomain.com` today, a different
one tomorrow. The censor sees an ever-changing name that always resolves (wildcard
A record) and always has a valid cert (issued per-name, automatically), so no
single SNI string can be blocklisted, and only a PSK holder knows which name is
ours. One wildcard DNS record, daily rotation (well under Let's Encrypt limits).

**Encrypted DNS (DoH), optional.** The relay can resolve the exit's hostname over
DoH (e.g. `https://cloudflare-dns.com/dns-query`) so the lookup itself is hidden —
the censor sees ordinary DoH to a big resolver, not the hostname. (The data still
goes to the exit's IP, which is visible; DoH hides the lookup, not the data path.)

> Note: `browser` pulls in the `quic-go` library (for real HTTP/3); `udp` and
> `reality-udp` remain pure Go standard library. Building needs GitHub reachable
> (the build fetches modules directly — see `build.sh`).

### `reality-udp` — QUIC masquerade

The opening packet is a genuine **QUIC Initial** whose payload is a TLS 1.3
ClientHello carrying a **real SNI** (e.g. `www.cloudflare.com`). A DPI inspecting
QUIC derives the standard Initial keys from the connection ID (the salt is public,
RFC 9001 §5.2), decrypts the packet, sees an ordinary HTTP-3 handshake to an
allowed site, and lets it pass — it cannot block that without breaking real
QUIC/HTTP-3 for everyone. Hidden inside the ClientHello is a **PSK-keyed auth
token**, shaped like the random GREASE value Chrome itself sends, so the exit
tells our client apart from a real browser or an active prober (which simply gets
no reply — a dead QUIC endpoint). After the handshake both ends switch to the
reliable-UDP data phase, framed as QUIC 1-RTT packets, so the whole flow stays
UDP to one address, consistent with a live QUIC session.

بسته‌ی آغازین یک **QUIC Initial واقعی** است که داخلش یک ClientHello با **SNI واقعی**
قرار دارد؛ از نگاهِ DPI یک هندشیکِ معمولیِ HTTP-3 به یک سایتِ مجاز دیده می‌شود. یک
توکنِ احراز هویتِ مبتنی بر PSK، هم‌شکلِ مقدارِ تصادفیِ GREASE، داخلِ ClientHello
پنهان است تا خروجی، کلاینتِ ما را از مرورگرِ واقعی/پروبر تشخیص دهد. بعد از هندشیک،
داده روی لایه‌ی UDP قابل‌اطمینان و به‌شکلِ بسته‌های QUIC 1-RTT جابه‌جا می‌شود.

---

## Architecture / معماری

```
  client app ──TCP/UDP──►  TVtunX relay :PORT  ══ encrypted mux over UDP ══►  TVtunX exit ──►  DEST
  (v2rayN…)    on relay IP     (inner side)      AEAD handshake + frames        (abroad)       e.g. 127.0.0.1:8443
```

- You define **forwards** on the relay: `RELAY_PORT -> DEST_HOST:DEST_PORT`.
- A client connects to `RELAY_IP:RELAY_PORT`; the exit dials `DEST_HOST:DEST_PORT`.
- Both **TCP and UDP** are forwarded on each port.
- The relay IP is what your client points at, so the **exit IP never appears** in
  your client config.

### Layers / لایه‌ها

1. **Carrier** — the transport's UDP carrier (`udp` reliable-UDP, `reality-udp`
   QUIC masquerade, or `browser` HTTP/3) **with a TCP fallback carrier on the same
   port** (TLS + PSK knock). The relay chooses UDP or TCP automatically (`-net auto`).
2. **PSK handshake** — a probe-resistant authenticated key exchange; a wrong PSK
   gets no usable reply.
3. **Frame layer** — authenticated encryption with length hiding and padding.
4. **Mux** — many TCP/UDP flows multiplexed over a small pool of carrier
   connections, with per-stream flow control.

> Crypto note: every primitive is Go standard library (AES-GCM, HKDF, HMAC,
> X25519) — nothing hand-rolled. The original work is in the framing, the
> reliable-UDP carrier, and the QUIC masquerade.

---

## Install / نصب

On a fresh Linux server (run as root). The interactive menu installs the exit or
relay role, sets up a `systemd` service, tunes the kernel (BBR, buffers,
forwarding) and opens the firewall port:

```sh
sudo bash deploy/install.sh
```

- On the **exit** (abroad): choose *Install exit*, pick a transport, pick a UDP
  port. It prints a **pre-shared key** — copy it.
- On the **relay** (inner side): choose *Install relay*, paste the key, enter the
  exit IP + port, your config port(s) to forward, and (for `reality-udp`) a
  disguise SNI. Point your client app at the **relay IP** and the same port(s).

Both ends must use the **same PSK, the same transport, and the same UDP port.**

### Manual (without the menu) / دستی

```sh
# once — generate a key, use the SAME value on both ends
tvtunx keygen

# exit (abroad)
tvtunx server -listen 0.0.0.0:443 -psk 'PASTE_KEY' -transport reality-udp

# relay (inner side)
tvtunx client -server <EXIT_IP>:443 -psk 'PASTE_KEY' -transport reality-udp \
              -sni www.cloudflare.com -forward 443:127.0.0.1:8443

# verify, end to end
tvtunx diag  -server <EXIT_IP>:443 -psk 'PASTE_KEY' -transport reality-udp -sni www.cloudflare.com
tvtunx bench -server <EXIT_IP>:443 -psk 'PASTE_KEY' -transport reality-udp -sni www.cloudflare.com
```

## Multiple tunnels per server / چند تانل روی یک سرور

Each tunnel is a **named instance**. One box can run several at once — one exit
serving several Iran relays, or one Iran relay reaching several exits — each with
its own name, port, key and (for reality-udp) SNI. The installer auto-suggests a
name (`t1`, `t2`, …) and manages each as its own `systemd` service
(`tvtunx-server@<name>` / `tvtunx-client@<name>`). *Add exit/relay tunnel* in the
menu creates another; *Edit / Test / Benchmark / Uninstall* let you pick which one.

هر تانل یک **instanceِ نام‌دار** است. یک سرور می‌تواند چند تانل هم‌زمان داشته باشد —
یک خارج به چند ایران، یا یک ایران به چند خارج — هرکدام با نام/پورت/کلید/SNIِ خودش.
نصاب به‌صورت خودکار یک نام پیشنهاد می‌دهد و هرکدام را به‌عنوانِ سرویسِ جداگانه مدیریت
می‌کند. روی یک خارج، چند رله می‌توانند به **همان** تانل/پورت وصل شوند؛ تانلِ دوم فقط
وقتی لازم است که کلید/پورتِ جدا بخواهی. روی رله، برای هر خارج از **پورت‌های کانفیگِ
متفاوت** استفاده کن (یک پورت را فقط یک تانل می‌تواند باز کند).

> Note: on the exit, one tunnel already serves many relays on its port. On the
> relay, give each tunnel distinct local config ports (a port is opened by only
> one tunnel).

## Typical use with a VLESS/VMess panel / کاربرد با پنل

1. On the **exit**, run your panel (X-UI / 3x-ui / Xray) listening on, say,
   `127.0.0.1:8443`.
2. On the **relay**, add a forward `443:127.0.0.1:8443`.
3. In your client app, build the config with **address = the relay's public IP**
   and **port = 443**. The exit IP stays hidden.

## Uninstall / cleanup / حذف کامل

Run the menu and choose *Uninstall* (remove one tunnel or all), or do it directly
on **each** server — this stops every named instance and removes everything:

```sh
# stop & disable every tunnel instance
for u in $(systemctl list-units --all --plain --no-legend 'tvtunx-*@*' | awk '{print $1}'); do
  sudo systemctl disable --now "$u" 2>/dev/null || true
done
sudo rm -f /etc/systemd/system/tvtunx-server@.service /etc/systemd/system/tvtunx-client@.service
sudo systemctl daemon-reload
sudo rm -rf /etc/tvtunx /usr/local/bin/tvtunx /etc/sysctl.d/99-tvtunx.conf
```

---

## Commands / دستورها

| command | purpose |
|---------|---------|
| `tvtunx keygen` | generate a secure PSK |
| `tvtunx server -listen H:P -psk KEY -transport T` | run the exit role |
| `tvtunx client -server H:P -psk KEY -transport T -forward P:H:P` | run the relay (repeat `-forward`) |
| `tvtunx diag  -server H:P -psk KEY -transport T` | test tunnel health end to end |
| `tvtunx bench -server H:P -psk KEY -transport T` | measure throughput & latency |

`T` is `reality-udp` (then also pass `-sni <real-site>`) or `udp`. Forward format
is `LISTEN_PORT:DEST_HOST:DEST_PORT`. `-udp-target N` paces the carrier to N Mbit/s
(0 = unpaced). `-pool N` opens N parallel carriers to beat per-flow throttling.

---

## Build from source / ساخت از سورس

Requires Go 1.24+. No network or modules to fetch — it is pure standard library:

```sh
./build.sh 1.0.0      # static binaries into dist/ for amd64, arm64, arm
go test ./...         # run the test suite
```

---

## Security / امنیت

TVtunX **reports and suggests; it never changes your config or acts on its own.**
Diagnostics print findings and recommendations for you to apply by hand. See
[SECURITY.md](SECURITY.md) for the threat model, what the masquerade does and does
not hide, and operational guidance. If you pasted any server password while
setting this up, rotate it.

## License

MIT — see [LICENSE](LICENSE).
