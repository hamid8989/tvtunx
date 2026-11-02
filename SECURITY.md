# SECURITY — بخوانید / Read this

این کور عمداً چند تصمیم امنیتی گرفته که برای کسی که از داخل ایران کار می‌کند مهم‌اند.
This core makes a few deliberate security choices that matter when operating from inside Iran.

## ۱. مقاومت در برابر active probing
سرور به کلاینتی که PSK درست ندارد **هیچ بایتی پاسخ نمی‌دهد**؛ سوکت را چند ثانیه باز نگه می‌دارد و هر چه بفرستند را می‌بلعد، سپس می‌بندد. یک prober نمی‌تواند تونل را از یک سرویس خاموش تشخیص دهد. (تست‌شده در `internal/handshake/handshake_test.go`.)

The server sends **zero bytes** to a client without the correct PSK, soaking input then dropping it. A prober cannot tell the tunnel apart from a dead service. (Verified by the test suite.)

## ۲. بدون حلقهٔ خودکارِ چرخش پارامتر
یک حلقه که تا «۱۰۰٪ پایداری» خودکار SNI/پورت/پروتکل را عوض کند، روی یک IP داخل ایران خطرناک است: probe مکرر به مقصدهای محدود + چرخش سریع = امضای قابل‌تشخیص که منجر به flag شدن IP و در بدترین حالت ارتباط با صاحب سرور می‌شود. به‌جایش `tvtunx diag` **گزارش و پیشنهاد** می‌دهد و تصمیم با شماست.

No autonomous "auto-healing" loop. On a box physically in Iran, rapid probing + parameter cycling is exactly the detectable pattern that gets an IP flagged. `diag` reports and suggests; you decide.

## ۳. رازها در فایل محیط، نه در کد
PSK در `/etc/tvtunx/*.env` با مجوز `600` نگه داشته می‌شود، نه داخل باینری یا اسکریپت. `install.sh` هیچ IP یا کلیدی hardcode نمی‌کند — همه را هنگام اجرا می‌پرسد، پس برای اشتراک‌گذاری عمومی امن است.

Secrets live in `/etc/tvtunx/*.env` (mode 600), never in the binary or script. `install.sh` hardcodes no IPs or keys.

## توصیه‌های عملیاتی | operational notes
- PSK را با `tvtunx keygen` بسازید و فقط از کانال امن به سرور دوم منتقل کنید.
- پورت ۴۴۳ معمولاً کم‌جلب‌توجه‌ترین است؛ اگر مسدود شد، پورت را دستی عوض کنید و دوباره `diag` بزنید.
- SOCKS5 را فقط روی `127.0.0.1` باز بگذارید (پیش‌فرض) تا از بیرون قابل‌دسترس نباشد.
- احراز هویت پسوردی SSH را روی هر دو سرور غیرفعال کنید و فقط کلید بگذارید.

## ۴. استتارِ QUIC در `reality-udp` / QUIC masquerade (`reality-udp`)

The `reality-udp` transport dresses the opening packet as a real **QUIC v1
Initial** carrying a TLS 1.3 ClientHello with a **real SNI** (e.g.
`www.cloudflare.com`). A DPI that parses QUIC decrypts the Initial with the
public, connection-ID-derived keys (RFC 9001 §5.2), reads an ordinary HTTP-3
handshake to an allowed site, and passes it. Our client is told apart from a real
browser by a **PSK-keyed auth token** hidden as a GREASE-shaped QUIC transport
parameter; without the PSK, the exit stays **completely silent** (a dead QUIC
endpoint), so an active prober that replays or forges an Initial learns nothing.
After the handshake, the data phase is QUIC-1-RTT-shaped and PSK-keyed, so a
passive DPI sees only consistent UDP to one 4-tuple.

**What this is and is NOT — read before deploying:**

- Strong against **SNI-allowlist and QUIC-structure DPI** (the common deployed
  case): the packet parses as valid QUIC and the SNI is a real allowed site.
- Strong against **active probing**: no valid PSK ⇒ no reply at all.
- **Not** a bit-perfect Chrome **QUIC fingerprint**. The ClientHello is
  Chrome-*shaped* (GREASE, the TLS 1.3 suites, h3 ALPN, QUIC transport params)
  but hand-built, not emitted by a real QUIC stack, so a censor doing exact
  QUIC-JA4 fingerprinting could still distinguish it.
- A censor correlating **SNI vs destination IP** can notice that "QUIC to
  Cloudflare's name" is going to your exit's IP rather than Cloudflare. Choose an
  SNI that is plausible for a server at your exit's provider/region.
- The masquerade **cannot be validated against a real DPI from a build
  environment.** Test it on the real path before relying on it; if `reality-udp`
  is blocked, try a different UDP port or the plain `udp` transport.

ترانسپورتِ `reality-udp` بسته‌ی آغازین را به‌شکلِ یک **QUIC Initial واقعی** با
**SNI واقعی** درمی‌آورد؛ DPI آن را مثلِ یک هندشیکِ HTTP-3 به سایتِ مجاز می‌بیند و
عبور می‌دهد. کلاینتِ ما با یک توکنِ PSK پنهان (هم‌شکلِ GREASE) شناخته می‌شود و بدونِ
PSK خروجی **کاملاً خاموش** می‌ماند. نکته‌ی صادقانه: این یک اثرانگشتِ **دقیقِ** QUICِ
کروم نیست و با DPIِ fingerprintِ دقیق ممکن است قابل‌تشخیص باشد؛ و چون نمی‌توان آن را
در محیطِ build مقابلِ DPIِ واقعی تست کرد، حتماً روی مسیرِ واقعی امتحانش کنید و اگر
مسدود شد پورتِ UDP را عوض کنید یا از ترانسپورتِ `udp` استفاده کنید.
