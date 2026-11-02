#!/usr/bin/env bash
# ===========================================================================
#  TVtunX installer & control menu
#  Raw TCP+UDP port-forwarding tunnel. Interactive menu: install exit/relay,
#  test the tunnel, show status, uninstall. English only.
# ===========================================================================
set -uo pipefail

if [[ -t 1 ]]; then
  R='\033[31m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; M='\033[35m'; D='\033[2m'; B='\033[1m'; X='\033[0m'
else
  R=''; G=''; Y=''; C=''; M=''; D=''; B=''; X=''
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG=/etc/tvtunx
BIN=/usr/local/bin/tvtunx

hr(){ printf "${D}  ────────────────────────────────────────────────────────${X}\n"; }
say(){ printf "${C}${B}>>${X} %s\n" "$*"; }
ok(){  printf "  ${G}OK${X} %s\n" "$*"; }
warn(){ printf "  ${Y}! ${X} %s\n" "$*"; }
err(){ printf "  ${R}x %s${X}\n" "$*" >&2; }
field(){ printf "    ${D}%-20s${X} ${B}%s${X}\n" "$1" "$2"; }
pause(){ echo; read -rp "  Press Enter to continue... " _; }

banner(){
  printf "\n${C}${B}  ████████╗██╗   ██╗████████╗██╗   ██╗███╗   ██╗██╗  ██╗${X}\n"
  printf "${C}${B}  ╚══██╔══╝██║   ██║╚══██╔══╝██║   ██║████╗  ██║╚██╗██╔╝${X}\n"
  printf "${C}${B}     ██║   ██║   ██║   ██║   ██║   ██║██╔██╗ ██║ ╚███╔╝ ${X}\n"
  printf "${C}${B}     ██║   ╚██╗ ██╔╝   ██║   ██║   ██║██║╚██╗██║ ██╔██╗ ${X}\n"
  printf "${C}${B}     ██║    ╚████╔╝    ██║   ╚██████╔╝██║ ╚████║██╔╝ ██╗${X}\n"
  printf "${C}${B}     ╚═╝     ╚═══╝     ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝${X}\n"
  printf "${D}  custom DPI-resistant TCP+UDP tunnel${X}\n"
}

# ---- host facts: public IP + country guess ----
PUBIP=""; COUNTRY=""; CC=""; GUESS=""
detect_host(){
  PUBIP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
        || curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null \
        || hostname -I 2>/dev/null | awk '{print $1}')
  # country via ip-api (free, no key). Fields: countryCode,country
  local geo
  geo=$(curl -fsS --max-time 5 "http://ip-api.com/line/?fields=countryCode,country" 2>/dev/null)
  if [[ -n "$geo" ]]; then
    CC=$(echo "$geo" | sed -n '1p')
    COUNTRY=$(echo "$geo" | sed -n '2p')
  fi
  if [[ "$CC" == "IR" ]]; then
    GUESS="relay"      # inside Iran -> relay role
  elif [[ -n "$CC" ]]; then
    GUESS="exit"       # anywhere else -> exit role
  fi
}

arch_bin(){
  case "$(uname -m)" in
    x86_64|amd64)      echo tvtunx-linux-amd64 ;;
    aarch64|arm64)     echo tvtunx-linux-arm64 ;;
    armv7l|armv6l|arm) echo tvtunx-linux-arm   ;;
    *) echo "" ;;
  esac
}

ensure_binary(){
  local b src; b=$(arch_bin)
  [[ -n "$b" ]] || { err "unsupported architecture: $(uname -m)"; return 1; }
  src="$SCRIPT_DIR/../dist/$b"; [[ -f "$src" ]] || src="$SCRIPT_DIR/$b"
  if [[ -f "$src" ]]; then
    # Always install the bundled binary so re-running the installer UPGRADES it
    # (the old behavior kept a stale binary if one already existed). install()
    # replaces the file atomically; running services pick it up on next restart.
    install -m 0755 "$src" "$BIN" && ok "installed $BIN ($b, $("$BIN" version 2>/dev/null))"
  elif [[ -x "$BIN" ]]; then
    warn "no bundled binary found; keeping existing $("$BIN" version 2>/dev/null)"
  else
    err "binary not found: $b (expected in ../dist/ or beside this script)"; return 1
  fi
  mkdir -p "$CFG" && chmod 700 "$CFG"
}

apply_sysctl(){
  cat >/etc/sysctl.d/99-tvtunx.conf <<'SYS'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
SYS
  sysctl --system >/dev/null 2>&1 || true
  ok "kernel tuning applied (BBR, forwarding, buffers)"
}

open_fw(){
  local port="$1"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then
    ufw allow "${port}/tcp" >/dev/null 2>&1 || true
    ufw allow "${port}/udp" >/dev/null 2>&1 || true
    ok "ufw: opened ${port}/tcp+udp"
  elif command -v nft >/dev/null 2>&1; then
    nft add rule inet filter input tcp dport "$port" accept >/dev/null 2>&1 || true
    nft add rule inet filter input udp dport "$port" accept >/dev/null 2>&1 || true
    ok "nftables: opened ${port}/tcp+udp"
  elif command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
    ok "iptables: opened ${port}/tcp+udp"
  else
    warn "no firewall detected; ensure ${port}/tcp+udp is reachable."
  fi
}

install_unit(){
  install -m 0644 "$SCRIPT_DIR/$1" "/etc/systemd/system/$1" 2>/dev/null || cp "$SCRIPT_DIR/$1" /etc/systemd/system/
}

# choose_transport -> sets global TR to "reality-udp" or "udp"
TR="reality-udp"
choose_transport(){
  echo
  printf "  ${B}Transport${X} ${D}— how the two servers connect (same on both ends)${X}\n"
  hr
  printf "    ${B}1${X}  reality-udp  ${D}QUIC masquerade over reliable-UDP: the opening packet${X}\n"
  printf "                   ${D}looks like a real Chrome HTTP/3 handshake to an allowed site,${X}\n"
  printf "                   ${D}and the carrier is loss-tolerant (no TCP-over-TCP meltdown).${X}\n"
  printf "                   ${D}Best against DPI + throttling. ${B}Recommended.${X}\n"
  printf "    ${B}2${X}  udp          ${D}plain reliable-UDP: fastest, lowest overhead; obfuscated${X}\n"
  printf "                   ${D}but not disguised as a named protocol. Use on links that only${X}\n"
  printf "                   ${D}throttle UDP rather than classify it.${X}\n"
  printf "    ${B}3${X}  browser      ${D}REAL HTTP/3 to a real site: the exit gets a free SSL cert${X}\n"
  printf "                   ${D}for your domain and serves a real website; the relay connects${X}\n"
  printf "                   ${D}like a browser. Not imitation — it IS browser traffic. Needs a${X}\n"
  printf "                   ${D}domain (one DNS record). Strongest realism.${X}\n"
  hr
  read -rp "  choose [1]: " _tr; _tr=${_tr:-1}
  case "$_tr" in
    2) TR="udp" ;;
    3) TR="browser" ;;
    *) TR="reality-udp" ;;
  esac
}

# ---- role install flows (both transports are UDP-carried; no TLS, no cert) ----
# ───────────────────────── instances ─────────────────────────
# Each tunnel is a NAMED systemd instance: config in /etc/tvtunx/<name>.<role>.env
# and service tvtunx-<server|client>@<name>. One box can run many: one exit to
# several Iran relays, or one Iran relay to several exits.
NAME_RE='^[a-zA-Z0-9][a-zA-Z0-9_-]{0,30}$'
server_env(){ echo "$CFG/$1.server.env"; }
client_env(){ echo "$CFG/$1.client.env"; }

# list_instances server|client -> prints instance names, one per line
list_instances(){
  local r="$1" f b
  shopt -s nullglob
  for f in "$CFG"/*.".$r.env" "$CFG"/*."$r".env; do
    [[ -f "$f" ]] || continue
    b=$(basename "$f"); echo "${b%.$r.env}"
  done
  shopt -u nullglob
}

# auto_name server|client -> next free tN
auto_name(){ local r="$1" i=1; while [[ -f "$CFG/t$i.$r.env" ]]; do i=$((i+1)); done; echo "t$i"; }

# ask_name server|client -> sets global NAME (auto-suggested, validated)
ask_name(){
  local r="$1" sug; sug=$(auto_name "$r")
  read -rp "  tunnel name [${sug}]: " NAME; NAME=${NAME:-$sug}
  if [[ ! "$NAME" =~ $NAME_RE ]]; then err "bad name (letters, digits, - and _ only)"; return 1; fi
  if [[ -f "$(server_env "$NAME")" || -f "$(client_env "$NAME")" ]]; then
    warn "a tunnel named '${NAME}' already exists here — it will be reconfigured."
  fi
  return 0
}

# ───────────────────────── role install flows ─────────────────────────
install_exit(){
  ensure_binary || { pause; return; }
  choose_transport
  ask_name server || { pause; return; }
  case "$TR" in
    udp)     install_exit_udp ;;
    browser) install_exit_browser ;;
    *)       install_exit_realityudp ;;
  esac
}

install_relay(){
  ensure_binary || { pause; return; }
  choose_transport
  ask_name client || { pause; return; }
  case "$TR" in
    udp)     install_relay_udp ;;
    browser) install_relay_browser ;;
    *)       install_relay_realityudp ;;
  esac
}

# write_server_env NAME TRANSPORT LISTEN PSK EXTRA
write_server_env(){
  local f; f=$(server_env "$1")
  cat >"$f" <<ENV
TVTUNX_NAME=$1
TVTUNX_TRANSPORT=$2
TVTUNX_LISTEN=$3
TVTUNX_PSK=$4
TVTUNX_PAD=512
TVTUNX_WINDOW=1024
TVTUNX_EXTRA=$5
ENV
  chmod 600 "$f"
}

# finish_exit NAME TRANSPORT LISTEN_PORT PSK
finish_exit(){
  local name="$1" tr="$2" lp="$3" psk="$4"
  install_unit tvtunx-server@.service
  systemctl daemon-reload
  systemctl enable "tvtunx-server@${name}" >/dev/null 2>&1
  systemctl restart "tvtunx-server@${name}" >/dev/null 2>&1  # restart (not just start) so a reconfigure reloads the new env
  ok "exit tunnel '${name}' is up (${tr})"
  echo; hr
  printf "  ${B}EXIT TUNNEL '${name}' READY${X}  ${D}(transport: ${tr})${X}\n"
  field "public IP" "${PUBIP:-unknown}"
  field "tunnel listen (UDP)" "0.0.0.0:${lp}"
  field "service" "tvtunx-server@${name}"
  hr
  echo
  printf "  ${B}Pre-shared key — paste this on the RELAY (same transport + port + name's choice):${X}\n\n"
  printf "      ${G}${B}%s${X}\n\n" "$psk"
  printf "  ${Y}Open UDP port ${lp} here (incl. any cloud firewall). One exit tunnel already${X}\n"
  printf "  ${Y}serves MANY relays on this port; add another exit tunnel only for a separate${X}\n"
  printf "  ${Y}key/port.${X}\n"
  pause
}

install_exit_udp(){
  echo
  printf "  ${D}udp carrier on this port. Open it for UDP (incl. any cloud firewall).${X}\n"
  read -rp "  tunnel link port (UDP) [443]: " LP; LP=${LP:-443}
  local PSK; PSK=$("$BIN" keygen)
  apply_sysctl
  open_fw "$LP"
  write_server_env "$NAME" udp "0.0.0.0:${LP}" "$PSK" "-transport udp"
  finish_exit "$NAME" udp "$LP" "$PSK"
}

install_exit_realityudp(){
  echo
  printf "  ${D}reality-udp: opening packet disguised as QUIC/HTTP-3 to a real site. The${X}\n"
  printf "  ${D}disguise SNI must be the SAME on exit and relay (e.g. www.cloudflare.com).${X}\n"
  read -rp "  tunnel link port (UDP) [443]: " LP; LP=${LP:-443}
  read -rp "  disguise SNI [www.cloudflare.com]: " SNI; SNI=${SNI:-www.cloudflare.com}
  local PSK; PSK=$("$BIN" keygen)
  apply_sysctl
  open_fw "$LP"
  write_server_env "$NAME" reality-udp "0.0.0.0:${LP}" "$PSK" "-transport reality-udp -sni ${SNI}"
  envset "$(server_env "$NAME")" TVTUNX_SNI "$SNI"
  finish_exit "$NAME" reality-udp "$LP" "$PSK"
}

# check_dns_points_here DOMAIN -> warn (don't block) if DOMAIN doesn't resolve to us
check_dns_points_here(){
  local dom="$1" ip=""
  if command -v getent >/dev/null 2>&1; then ip=$(getent ahostsv4 "$dom" 2>/dev/null | awk '{print $1; exit}'); fi
  [[ -z "$ip" ]] && command -v dig >/dev/null 2>&1 && ip=$(dig +short A "$dom" 2>/dev/null | head -1)
  [[ -z "$ip" ]] && command -v host >/dev/null 2>&1 && ip=$(host -t A "$dom" 2>/dev/null | awk '/has address/{print $NF; exit}')
  if [[ -z "$ip" ]]; then
    warn "could not resolve ${dom} yet — DNS may still be propagating (that's OK, it can take a few minutes)."
  elif [[ -n "$PUBIP" && "$ip" != "$PUBIP" ]]; then
    warn "${dom} currently points to ${ip}, not this server (${PUBIP}). Fix the A record, or wait for propagation."
  else
    ok "${dom} points here (${ip})."
  fi
}

# port_busy PORT -> true if something is already listening on TCP PORT
port_busy(){ ss -tlnH "sport = :$1" 2>/dev/null | grep -q .; }

install_exit_browser(){
  echo
  printf "  ${D}browser transport: this exit hosts a REAL website on your domain with a free${X}\n"
  printf "  ${D}Let's Encrypt certificate, over HTTP/3 (UDP). The relay connects like a${X}\n"
  printf "  ${D}browser; the tunnel rides inside.${X}\n"
  echo
  read -rp "  Enter a domain you own (e.g. cdn.example.com): " DOM
  [[ -n "$DOM" ]] || { err "a domain is required for the browser transport"; pause; return; }
  read -rp "  tunnel link port (UDP) [443]: " LP; LP=${LP:-443}
  echo
  printf "  ${D}Rotating subdomains change the hostname daily (harder to block a single name).${X}\n"
  read -rp "  Use rotating subdomains? [Y/n]: " ROT; ROT=${ROT:-Y}
  local LABEL="t"
  [[ "$ROT" =~ ^[Yy]$ ]] && { read -rp "  wildcard label [t]: " LABEL; LABEL=${LABEL:-t}; }

  # Decide how to get the SSL certificate.
  echo
  local CERTMODE="http01" CFTOK=""
  if port_busy 80; then
    local who; who=$(ss -tlnpH 'sport = :80' 2>/dev/null | grep -oP 'users:\(\("\K[^"]+' | head -1)
    printf "  ${Y}Port 80 is already in use (by '%s'), so the automatic (HTTP-01) method${X}\n" "${who:-another service}"
    printf "  ${Y}can't be used. We'll get the certificate via DNS instead (no port needed).${X}\n"
    CERTMODE="dns01"
  else
    printf "  ${D}Certificate method:${X}\n"
    printf "    ${B}1${X}  Automatic via port 80 ${D}(simplest; needs :80/tcp free + open)${X}\n"
    printf "    ${B}2${X}  DNS ${D}(no port needed — use if :80 may be taken later, e.g. a panel node)${X}\n"
    read -rp "  choose [1]: " cm; cm=${cm:-1}
    [[ "$cm" == 2 ]] && CERTMODE="dns01"
  fi

  if [[ "$CERTMODE" == dns01 ]]; then
    echo
    printf "  ${D}DNS method: either paste a Cloudflare API token (Zone:DNS:Edit) to do it${X}\n"
    printf "  ${D}automatically, or leave blank to add one TXT record yourself.${X}\n"
    read -rp "  Cloudflare API token [blank = manual]: " CFTOK
    echo
    printf "  ${B}First, create this wildcard record (so the hostnames resolve to this server):${X}\n\n"
    printf "      Type:  ${B}A${X}    Name:  ${B}*.%s.%s${X}    Value: ${B}%s${X}    Proxy: ${B}OFF${X}\n\n" "$LABEL" "$DOM" "${PUBIP:-<this server IP>}"
    read -rp "  Press Enter when the A record is created... " _
    mkdir -p "$CFG/acme"
    say "Getting the wildcard certificate via DNS-01 ..."
    local dnsmode="manual"; [[ -n "$CFTOK" ]] && dnsmode="cloudflare"
    if "$BIN" cert -domain "$DOM" -label "$LABEL" -acme-dir "$CFG/acme" -dns "$dnsmode" ${CFTOK:+-cf-token "$CFTOK"}; then
      ok "certificate obtained"
    else
      err "certificate step failed — fix the DNS/token and re-run: tvtunx cert -domain ${DOM} -label ${LABEL} -acme-dir ${CFG}/acme -dns ${dnsmode}"
      warn "continuing; the tunnel won't connect until the certificate exists."
    fi
  else
    echo
    printf "  ${B}Create ONE DNS record, then press Enter:${X}\n\n"
    printf "      Type:  ${B}A${X}    Name:  ${B}*.%s.%s${X}    Value: ${B}%s${X}    Proxy: ${B}OFF${X}\n\n" "$LABEL" "$DOM" "${PUBIP:-<this server IP>}"
    read -rp "  Press Enter when the A record is created... " _
    open_fw 80  # ACME HTTP-01 challenge
  fi

  local PSK; PSK=$("$BIN" keygen)
  apply_sysctl
  open_fw "$LP"     # HTTP/3 (UDP)
  mkdir -p "$CFG/acme"
  local EXTRA="-transport browser -domain ${DOM} -label ${LABEL}"
  [[ -n "$CFTOK" ]] && EXTRA="$EXTRA -cf-token ${CFTOK}"
  write_server_env "$NAME" browser "0.0.0.0:${LP}" "$PSK" "$EXTRA"
  envset "$(server_env "$NAME")" TVTUNX_DOMAIN "$DOM"
  envset "$(server_env "$NAME")" TVTUNX_LABEL "$LABEL"
  [[ -n "$CFTOK" ]] && envset "$(server_env "$NAME")" TVTUNX_CF_TOKEN "$CFTOK"
  printf "  ${Y}On the relay use the SAME domain (${B}%s${X}${Y}) + label (${B}%s${X}${Y}) + PSK.${X}\n" "$DOM" "$LABEL"
  finish_exit "$NAME" browser "$LP" "$PSK"
}

# collect common relay inputs into globals: SRV LP PSK CPLIST PROTO UT FWDS FSUM
relay_common_inputs(){
  read -rp "  exit server IP: " SRV
  read -rp "  tunnel link port (UDP, same as exit) [443]: " LP; LP=${LP:-443}
  read -rp "  pre-shared key (from the exit server): " PSK
  if [[ -z "$SRV" || -z "$PSK" ]]; then err "exit IP and PSK are required"; return 1; fi
  echo
  printf "  ${D}Config port(s) your VLESS/VMESS use. The relay opens each here and the exit${X}\n"
  printf "  ${D}delivers it to 127.0.0.1:<same port>. Space-separated for several.${X}\n"
  printf "  ${D}NOTE: a port can be opened by only ONE tunnel on this relay — use distinct${X}\n"
  printf "  ${D}config ports for different exits.${X}\n"
  read -rp "  config port(s) to forward: " CPLIST
  [[ -n "$CPLIST" ]] || { err "at least one config port is required"; return 1; }
  echo
  read -rp "  protocol [both/tcp/udp] (Enter = both): " PROTO; PROTO=${PROTO:-both}
  case "$PROTO" in both|tcp|udp) ;; *) warn "unknown value, using both"; PROTO=both ;; esac
  echo
  printf "  ${D}Speed target in Mbit/s for udp/reality-udp (Hysteria-style 'Brutal' mode:${X}\n"
  printf "  ${D}holds this rate through packet loss instead of slowing down — set it near${X}\n"
  printf "  ${D}your real download speed, e.g. 50). 0 = adaptive/unpaced. (browser ignores${X}\n"
  printf "  ${D}this; it uses QUIC's own control.)${X}\n"
  read -rp "  speed target Mbit/s [0]: " UT; UT=${UT:-0}
  [[ "$UT" =~ ^[0-9]+$ ]] || UT=0
  apply_sysctl
  FWDS=""; FSUM=""
  local p
  for p in $CPLIST; do
    [[ "$p" =~ ^[0-9]+$ ]] || { warn "skipping invalid port '$p'"; continue; }
    if port_taken_by_other "$NAME" "$p"; then warn "port ${p} is already forwarded by another tunnel on this relay — skipping"; continue; fi
    FWDS="$FWDS -forward ${p}:127.0.0.1:${p}"
    FSUM="${FSUM}    :${p} (${PROTO}) -> exit 127.0.0.1:${p}\n"
    open_fw "$p"
  done
  FWDS="${FWDS# }"
  [[ -n "$FWDS" ]] || { err "no valid config ports"; return 1; }
  open_fw "$LP"
  return 0
}

# port_taken_by_other NAME PORT -> true if another client instance forwards PORT
port_taken_by_other(){
  local me="$1" port="$2" n
  for n in $(list_instances client); do
    [[ "$n" == "$me" ]] && continue
    envval "$(client_env "$n")" TVTUNX_CONFIG_PORT | tr ' ' '\n' | grep -qx "$port" && return 0
  done
  return 1
}

# finish_relay NAME TRANSPORT
finish_relay(){
  local name="$1" tr="$2"
  install_unit tvtunx-client@.service
  systemctl daemon-reload
  systemctl enable "tvtunx-client@${name}" >/dev/null 2>&1
  systemctl restart "tvtunx-client@${name}" >/dev/null 2>&1  # restart (not just start) so a reconfigure reloads the new env
  ok "relay tunnel '${name}' is up (${tr})"
  echo; hr
  printf "  ${B}RELAY TUNNEL '${name}' READY${X}  ${D}(transport: ${tr})${X}\n"
  field "relay public IP" "${PUBIP:-unknown}"
  field "exit server (UDP)" "${SRV}:${LP}"
  printf "    ${D}forwards:${X}\n"
  printf "${FSUM}"
  field "service" "tvtunx-client@${name}"
  hr
  echo
  printf "  In your client app, set ${B}address = ${PUBIP:-<this relay IP>}${X} and use any of the ports above.\n"
  printf "  ${Y}${B}Open UDP port ${LP} on BOTH servers (incl. cloud firewall).${X}\n"
  pause
}

install_relay_udp(){
  echo
  relay_common_inputs || { pause; return; }
  local EXTRA="-transport udp"
  [[ "$UT" -gt 0 ]] 2>/dev/null && EXTRA="$EXTRA -udp-target ${UT}"
  local f; f=$(client_env "$NAME")
  cat >"$f" <<ENV
TVTUNX_NAME=${NAME}
TVTUNX_TRANSPORT=udp
TVTUNX_SERVER=${SRV}:${LP}
TVTUNX_PSK=${PSK}
TVTUNX_PAD=512
TVTUNX_WINDOW=1024
TVTUNX_SNI=
TVTUNX_PROTO=${PROTO}
TVTUNX_CONFIG_PORT=${CPLIST}
TVTUNX_UDP_TARGET=${UT}
TVTUNX_FORWARDS=${FWDS}
TVTUNX_EXTRA=${EXTRA}
ENV
  chmod 600 "$f"
  finish_relay "$NAME" udp
}

install_relay_realityudp(){
  echo
  printf "  ${D}disguise SNI = a real HTTP/3 site, SAME as the exit (e.g. www.cloudflare.com,${X}\n"
  printf "  ${D}www.google.com, www.bing.com).${X}\n"
  read -rp "  disguise SNI [www.cloudflare.com]: " SNI; SNI=${SNI:-www.cloudflare.com}
  echo
  relay_common_inputs || { pause; return; }
  local EXTRA="-transport reality-udp -sni ${SNI}"
  [[ "$UT" -gt 0 ]] 2>/dev/null && EXTRA="$EXTRA -udp-target ${UT}"
  local f; f=$(client_env "$NAME")
  cat >"$f" <<ENV
TVTUNX_NAME=${NAME}
TVTUNX_TRANSPORT=reality-udp
TVTUNX_SERVER=${SRV}:${LP}
TVTUNX_PSK=${PSK}
TVTUNX_PAD=512
TVTUNX_WINDOW=1024
TVTUNX_SNI=${SNI}
TVTUNX_PROTO=${PROTO}
TVTUNX_CONFIG_PORT=${CPLIST}
TVTUNX_UDP_TARGET=${UT}
TVTUNX_FORWARDS=${FWDS}
TVTUNX_EXTRA=${EXTRA}
ENV
  chmod 600 "$f"
  finish_relay "$NAME" reality-udp
}

install_relay_browser(){
  echo
  printf "  ${D}browser transport: connect to the exit's real domain over HTTP/3, like a${X}\n"
  printf "  ${D}browser. Use the SAME domain the exit was set up with.${X}\n"
  read -rp "  exit domain (e.g. cdn.example.com): " DOM
  [[ -n "$DOM" ]] || { err "domain is required"; pause; return; }
  read -rp "  rotating-subdomain label (SAME as exit; blank if the exit didn't use one): " LABEL
  echo
  printf "  ${D}Optional: resolve the exit's hostname over encrypted DNS (DoH) so the censor${X}\n"
  printf "  ${D}doesn't see the name in a plain DNS lookup. Press Enter to skip, or paste a${X}\n"
  printf "  ${D}DoH URL like https://cloudflare-dns.com/dns-query${X}\n"
  read -rp "  DoH endpoint [none]: " DOH
  echo
  relay_common_inputs || { pause; return; }
  local EXTRA="-transport browser -domain ${DOM}"
  [[ -n "$LABEL" ]] && EXTRA="$EXTRA -label ${LABEL}"
  [[ -n "$DOH" ]] && EXTRA="$EXTRA -doh ${DOH}"
  local f; f=$(client_env "$NAME")
  cat >"$f" <<ENV
TVTUNX_NAME=${NAME}
TVTUNX_TRANSPORT=browser
TVTUNX_SERVER=${SRV}:${LP}
TVTUNX_PSK=${PSK}
TVTUNX_PAD=512
TVTUNX_WINDOW=1024
TVTUNX_SNI=
TVTUNX_DOMAIN=${DOM}
TVTUNX_LABEL=${LABEL}
TVTUNX_DOH=${DOH}
TVTUNX_PROTO=${PROTO}
TVTUNX_CONFIG_PORT=${CPLIST}
TVTUNX_UDP_TARGET=${UT}
TVTUNX_FORWARDS=${FWDS}
TVTUNX_EXTRA=${EXTRA}
ENV
  chmod 600 "$f"
  finish_relay "$NAME" browser
}

envval(){ grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2-; }

# client_transport_flags ENVFILE -> the -transport (and -sni for reality-udp) flags
# diag/bench need, derived from a relay instance's client.env.
client_transport_flags(){
  local f="$1" tr sni dom lab doh x; tr=$(envval "$f" TVTUNX_TRANSPORT)
  case "$tr" in
    reality-udp) sni=$(envval "$f" TVTUNX_SNI); echo "-transport reality-udp -sni ${sni}" ;;
    browser)
      dom=$(envval "$f" TVTUNX_DOMAIN); lab=$(envval "$f" TVTUNX_LABEL); doh=$(envval "$f" TVTUNX_DOH)
      x="-transport browser -domain ${dom}"
      [[ -n "$lab" ]] && x="$x -label ${lab}"
      [[ -n "$doh" ]] && x="$x -doh ${doh}"
      echo "$x" ;;
    *)           echo "-transport udp" ;;
  esac
}

# envset FILE KEY VALUE -> replace (or append) KEY=VALUE in an env file, safely.
envset(){
  local file="$1" key="$2" val="$3" tmp
  tmp=$(mktemp)
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    while IFS= read -r line; do
      if [[ "$line" == "${key}="* ]]; then printf '%s=%s\n' "$key" "$val"; else printf '%s\n' "$line"; fi
    done <"$file" >"$tmp"
  else
    cat "$file" >"$tmp" 2>/dev/null
    printf '%s=%s\n' "$key" "$val" >>"$tmp"
  fi
  cat "$tmp" >"$file"
  rm -f "$tmp"
}

# pick_instance [server|client|any] -> sets PICK_NAME PICK_ROLE PICK_ENV PICK_UNIT.
# Auto-selects when exactly one matches; lists a menu when several; 1 if none.
PICK_NAME=""; PICK_ROLE=""; PICK_ENV=""; PICK_UNIT=""
pick_instance(){
  local want="${1:-any}" n items=() it
  if [[ "$want" == server || "$want" == any ]]; then for n in $(list_instances server); do items+=("exit:$n"); done; fi
  if [[ "$want" == client || "$want" == any ]]; then for n in $(list_instances client); do items+=("relay:$n"); done; fi
  if [[ ${#items[@]} -eq 0 ]]; then warn "no matching tunnel on this server yet."; return 1; fi
  local sel
  if [[ ${#items[@]} -eq 1 ]]; then
    sel="${items[0]}"
  else
    echo; say "Choose a tunnel"; hr
    local i=1
    for it in "${items[@]}"; do printf "    ${B}%d${X}  %-16s ${D}(%s)${X}\n" "$i" "${it#*:}" "${it%%:*}"; i=$((i+1)); done
    hr
    read -rp "  choose [1]: " c; c=${c:-1}
    [[ "$c" =~ ^[0-9]+$ ]] && (( c>=1 && c<=${#items[@]} )) || { warn "invalid"; return 1; }
    sel="${items[$((c-1))]}"
  fi
  PICK_ROLE="${sel%%:*}"; PICK_NAME="${sel#*:}"
  if [[ "$PICK_ROLE" == exit ]]; then PICK_ENV=$(server_env "$PICK_NAME"); PICK_UNIT="tvtunx-server@${PICK_NAME}"
  else PICK_ENV=$(client_env "$PICK_NAME"); PICK_UNIT="tvtunx-client@${PICK_NAME}"; fi
  return 0
}

# ---- test one tunnel ----
test_tunnel(){
  pick_instance any || { pause; return; }
  echo
  if [[ "$PICK_ROLE" == relay ]]; then
    local server psk cp tf
    server=$(envval "$PICK_ENV" TVTUNX_SERVER)
    psk=$(envval "$PICK_ENV" TVTUNX_PSK)
    cp=$(envval "$PICK_ENV" TVTUNX_CONFIG_PORT)
    tf=$(client_transport_flags "$PICK_ENV")
    say "Testing relay '${PICK_NAME}' to exit ${server}"
    "$BIN" diag -server "$server" -psk "$psk" -probe 1.1.1.1:80 $tf
    echo
    local p
    for p in $cp; do
      [[ "$p" =~ ^[0-9]+$ ]] || continue
      if timeout 6 bash -c "exec 3<>/dev/tcp/127.0.0.1/${p}" 2>/dev/null; then
        ok "config port ${p} is reachable through the tunnel (node answered)"
      else
        warn "config port ${p} did not answer — is the node listening on 127.0.0.1:${p} at the exit?"
      fi
    done
  else
    local lp
    lp=$(envval "$PICK_ENV" TVTUNX_LISTEN | awk -F: '{print $NF}')
    say "Exit tunnel '${PICK_NAME}'. Checking it is listening on UDP ${lp}."
    if ss -ulnp 2>/dev/null | grep -q ":${lp} "; then
      ok "listening on UDP ${lp}"; printf "  ${D}Full end-to-end test is run from the RELAY side.${X}\n"
    else
      warn "nothing on UDP ${lp}; is ${PICK_UNIT} running? (systemctl status ${PICK_UNIT})"
    fi
  fi
  pause
}

# est KB RTTms -> approximate per-connection Mbit/s (window*8/rtt)
_est(){ local r="$2"; [[ -z "$r" || "$r" -eq 0 ]] && r=80; echo $(( $1 * 8 / r )); }

# ---- benchmark one relay tunnel, then tune its speed profile ----
bench_tunnel(){
  pick_instance client || { pause; return; }
  local server psk tmp line thr rtt ram tf
  server=$(envval "$PICK_ENV" TVTUNX_SERVER)
  psk=$(envval "$PICK_ENV" TVTUNX_PSK)
  tf=$(client_transport_flags "$PICK_ENV")
  say "Benchmarking relay '${PICK_NAME}' to ${server} (takes ~15s) ..."
  echo
  tmp=$(mktemp)
  "$BIN" bench -server "$server" -psk "$psk" -secs 5 $tf | tee "$tmp"
  line=$(grep -m1 '^TVTUNX_BENCH' "$tmp" 2>/dev/null); rm -f "$tmp"
  thr=$(echo "$line" | sed -n 's/.*throughput_mbit=\([0-9.]*\).*/\1/p')
  rtt=$(echo "$line" | sed -n 's/.*idle_rtt_ms=\([0-9]*\).*/\1/p')
  [[ -z "$rtt" || "$rtt" -eq 0 ]] 2>/dev/null && rtt=80
  ram=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}'); [[ -z "$ram" ]] && ram=1024
  local rec
  if   [[ $ram -lt 1200 ]]; then rec=2
  elif [[ $ram -lt 2500 ]]; then rec=3
  else rec=4; fi
  echo; hr
  printf "  ${B}Speed profile for '${PICK_NAME}'${X}  ${D}(RTT ${rtt}ms · RAM ${ram}MB · current ${thr:-?} Mbit/s)${X}\n"
  hr
  printf "    ${B}1${X}  Light   ${D}512 KB  · ~$(_est 512 "$rtt") Mbit/s/conn — weak servers${X}\n"
  printf "    ${B}2${X}  Normal  ${D}1 MB    · ~$(_est 1024 "$rtt") Mbit/s/conn — typical${X}\n"
  printf "    ${B}3${X}  Fast    ${D}2 MB    · ~$(_est 2048 "$rtt") Mbit/s/conn — 2GB+${X}\n"
  printf "    ${B}4${X}  Max     ${D}4 MB    · ~$(_est 4096 "$rtt") Mbit/s/conn — 4GB+${X}\n"
  printf "    ${B}0${X}  keep current\n"
  hr
  printf "  ${G}${B}Recommended: %s${X}\n" "$rec"
  read -rp "  choose [${rec}]: " ch; ch=${ch:-$rec}
  local kb=""
  case "$ch" in 1) kb=512 ;; 2) kb=1024 ;; 3) kb=2048 ;; 4) kb=4096 ;; 0) pause; return ;; *) warn "invalid"; pause; return ;; esac
  envset "$PICK_ENV" TVTUNX_WINDOW "$kb"
  _restart "$PICK_UNIT"
  echo; ok "window set to ${kb} KB for '${PICK_NAME}'"
  warn "set the SAME window on the matching EXIT tunnel, or speed won't change."
  pause
}

# recompose a relay instance's TVTUNX_EXTRA from its stored fields.
recompose_client_extra(){
  local f="$1" tr sni ut dom lab doh x
  tr=$(envval "$f" TVTUNX_TRANSPORT); sni=$(envval "$f" TVTUNX_SNI); ut=$(envval "$f" TVTUNX_UDP_TARGET)
  dom=$(envval "$f" TVTUNX_DOMAIN); lab=$(envval "$f" TVTUNX_LABEL); doh=$(envval "$f" TVTUNX_DOH)
  case "$tr" in
    reality-udp) x="-transport reality-udp -sni ${sni}" ;;
    browser)
      x="-transport browser -domain ${dom}"
      [[ -n "$lab" ]] && x="$x -label ${lab}"
      [[ -n "$doh" ]] && x="$x -doh ${doh}" ;;
    *)           x="-transport udp" ;;
  esac
  [[ "$tr" != browser && "$ut" =~ ^[0-9]+$ && "$ut" -gt 0 ]] && x="$x -udp-target ${ut}"
  envset "$f" TVTUNX_EXTRA "$x"
}

# recompose an exit instance's TVTUNX_EXTRA from its stored fields.
recompose_server_extra(){
  local f="$1" tr sni dom lab x
  tr=$(envval "$f" TVTUNX_TRANSPORT); sni=$(envval "$f" TVTUNX_SNI); dom=$(envval "$f" TVTUNX_DOMAIN); lab=$(envval "$f" TVTUNX_LABEL)
  case "$tr" in
    reality-udp) x="-transport reality-udp"; [[ -n "$sni" ]] && x="$x -sni ${sni}" ;;
    browser)     x="-transport browser -domain ${dom}"; [[ -n "$lab" ]] && x="$x -label ${lab}" ;;
    *)           x="-transport udp" ;;
  esac
  envset "$f" TVTUNX_EXTRA "$x"
}

# ---- edit one tunnel, field by field ----
edit_tunnel(){
  pick_instance any || { pause; return; }
  local f="$PICK_ENV" unit="$PICK_UNIT" role="$PICK_ROLE" tr
  tr=$(envval "$f" TVTUNX_TRANSPORT)
  while :; do
    clear; banner; echo
    if [[ "$role" == exit ]]; then
      local lp ssni
      lp=$(envval "$f" TVTUNX_LISTEN | awk -F: '{print $NF}'); ssni=$(envval "$f" TVTUNX_SNI)
      say "Edit EXIT '${PICK_NAME}'  (transport: ${tr})"
      hr
      printf "    ${B}1${X}  tunnel link port   ${D}(current: %s — UDP)${X}\n" "$lp"
      printf "    ${B}2${X}  disguise SNI       ${D}(current: %s — reality-udp, must match relay)${X}\n" "${ssni:-<none>}"
      printf "    ${B}3${X}  regenerate PSK\n"
      printf "    ${B}4${X}  window (KB)        ${D}(current: %s)${X}\n" "$(envval "$f" TVTUNX_WINDOW)"
      printf "    ${B}0${X}  back\n"
      hr; read -rp "  choose: " e
      case "$e" in
        1) read -rp "  new link port: " v; [[ -n "$v" ]] && { envset "$f" TVTUNX_LISTEN "0.0.0.0:${v}"; open_fw "$v"; _restart "$unit"; warn "set the SAME port on the relay"; } ;;
        2) if [[ "$tr" != reality-udp ]]; then warn "SNI only applies to reality-udp"; else read -rp "  new disguise SNI: " v; [[ -n "$v" ]] && { envset "$f" TVTUNX_SNI "$v"; recompose_server_extra "$f"; _restart "$unit"; warn "set the SAME SNI on the relay"; }; fi ;;
        3) local np; np=$("$BIN" keygen); envset "$f" TVTUNX_PSK "$np"; _restart "$unit"; echo; printf "  new PSK (paste on relay): ${G}${B}%s${X}\n" "$np" ;;
        4) read -rp "  new window KB: " v; if [[ "$v" =~ ^[0-9]+$ ]]; then envset "$f" TVTUNX_WINDOW "$v"; _restart "$unit"; warn "set the SAME window on the relay"; else warn "must be a number"; fi ;;
        0) return ;; *) warn "invalid"; sleep 1 ;;
      esac
      [[ "$e" =~ ^[1234]$ ]] && pause
    else
      local srv lp sni cp proto
      srv=$(envval "$f" TVTUNX_SERVER | awk -F: '{print $1}'); lp=$(envval "$f" TVTUNX_SERVER | awk -F: '{print $2}')
      sni=$(envval "$f" TVTUNX_SNI); cp=$(envval "$f" TVTUNX_CONFIG_PORT); proto=$(envval "$f" TVTUNX_PROTO)
      say "Edit RELAY '${PICK_NAME}'  (transport: ${tr})"
      hr
      printf "    ${B}1${X}  exit server IP     ${D}(current: %s)${X}\n" "$srv"
      printf "    ${B}2${X}  tunnel link port   ${D}(current: %s — UDP)${X}\n" "$lp"
      printf "    ${B}3${X}  pre-shared key\n"
      printf "    ${B}4${X}  disguise SNI       ${D}(current: %s — reality-udp, must match exit)${X}\n" "${sni:-<none>}"
      printf "    ${B}5${X}  config port(s)     ${D}(current: %s)${X}\n" "$cp"
      printf "    ${B}6${X}  protocol           ${D}(current: %s)${X}\n" "$proto"
      printf "    ${B}7${X}  window (KB)        ${D}(current: %s)${X}\n" "$(envval "$f" TVTUNX_WINDOW)"
      printf "    ${B}0${X}  back\n"
      hr; read -rp "  choose: " e
      case "$e" in
        1) read -rp "  new exit IP: " v; [[ -n "$v" ]] && { envset "$f" TVTUNX_SERVER "${v}:${lp}"; _restart "$unit"; } ;;
        2) read -rp "  new link port: " v; [[ -n "$v" ]] && { envset "$f" TVTUNX_SERVER "${srv}:${v}"; _restart "$unit"; warn "set the SAME port on the exit"; } ;;
        3) read -rp "  new PSK: " v; [[ -n "$v" ]] && { envset "$f" TVTUNX_PSK "$v"; _restart "$unit"; } ;;
        4) if [[ "$tr" != reality-udp ]]; then warn "SNI only applies to reality-udp"; else read -rp "  new disguise SNI: " v; [[ -n "$v" ]] && { envset "$f" TVTUNX_SNI "$v"; recompose_client_extra "$f"; _restart "$unit"; warn "set the SAME SNI on the exit"; }; fi ;;
        5) read -rp "  new config port(s): " v
           if [[ -n "$v" ]]; then local nf="" p; for p in $v; do [[ "$p" =~ ^[0-9]+$ ]] && { nf="$nf -forward ${p}:127.0.0.1:${p}"; open_fw "$p"; }; done; nf="${nf# }"
             if [[ -n "$nf" ]]; then envset "$f" TVTUNX_CONFIG_PORT "$v"; envset "$f" TVTUNX_FORWARDS "$nf"; _restart "$unit"; else warn "no valid ports"; fi; fi ;;
        6) read -rp "  protocol [both/tcp/udp]: " v; case "$v" in both|tcp|udp) envset "$f" TVTUNX_PROTO "$v"; _restart "$unit" ;; *) warn "unknown" ;; esac ;;
        7) read -rp "  new window KB: " v; if [[ "$v" =~ ^[0-9]+$ ]]; then envset "$f" TVTUNX_WINDOW "$v"; _restart "$unit"; warn "set the SAME window on the exit"; else warn "must be a number"; fi ;;
        0) return ;; *) warn "invalid"; sleep 1 ;;
      esac
      [[ "$e" =~ ^[1234567]$ ]] && pause
    fi
  done
}

# restart_tunnel -> pick an instance and restart its service.
restart_tunnel(){
  pick_instance any || { pause; return; }
  _restart "$PICK_UNIT"
  pause
}

# _restart UNIT -> restart a specific systemd instance and report.
_restart(){
  local svc="$1"
  systemctl restart "$svc" 2>/dev/null
  sleep 1
  if systemctl is-active --quiet "$svc"; then ok "$svc restarted"; else err "$svc failed — check: journalctl -u $svc -n 20"; fi
}

live_log(){
  pick_instance any || { pause; return; }
  local unit="$PICK_UNIT" tmp jpid
  echo; say "Live log for ${unit} — press Enter to return"; hr
  tmp=$(mktemp)
  journalctl -u "$unit" -n 10 -f -o short 2>/dev/null >"$tmp" & jpid=$!
  while :; do
    if read -t 0.5 -r _ 2>/dev/null; then break; fi
    printf '\033[2J\033[H'; say "Live log for ${unit} — last 10 lines, press Enter to return"; hr
    tail -n 10 "$tmp" 2>/dev/null; hr
  done
  kill "$jpid" 2>/dev/null; wait "$jpid" 2>/dev/null; rm -f "$tmp"
}

show_status(){
  echo; say "Installed tunnels on this server"; hr
  local any=0 n st lp
  for n in $(list_instances server); do
    any=1; st=$(systemctl is-active "tvtunx-server@${n}" 2>/dev/null)
    lp=$(envval "$(server_env "$n")" TVTUNX_LISTEN | awk -F: '{print $NF}')
    printf "    ${B}%-16s${X} exit    ${D}UDP :%s${X}  %s\n" "$n" "$lp" "$([[ "$st" == active ]] && echo "${G}active${X}" || echo "${R}${st:-down}${X}")"
  done
  for n in $(list_instances client); do
    any=1; st=$(systemctl is-active "tvtunx-client@${n}" 2>/dev/null)
    local srv; srv=$(envval "$(client_env "$n")" TVTUNX_SERVER)
    printf "    ${B}%-16s${X} relay   ${D}-> %s${X}  %s\n" "$n" "$srv" "$([[ "$st" == active ]] && echo "${G}active${X}" || echo "${R}${st:-down}${X}")"
  done
  [[ "$any" == 1 ]] || echo "   (none installed yet)"
  echo; say "Listening UDP ports"
  ss -ulnp 2>/dev/null | grep -i tvtunx || echo "   (none — services may be down)"
  pause
}

# uninstall one tunnel, or everything on this server.
uninstall(){
  echo
  local names=() n
  for n in $(list_instances server); do names+=("exit:$n"); done
  for n in $(list_instances client); do names+=("relay:$n"); done
  if [[ ${#names[@]} -eq 0 ]]; then warn "nothing installed here."; pause; return; fi
  say "Remove which tunnel?"; hr
  local i=1 it
  for it in "${names[@]}"; do printf "    ${B}%d${X}  %-16s ${D}(%s)${X}\n" "$i" "${it#*:}" "${it%%:*}"; i=$((i+1)); done
  printf "    ${B}a${X}  ALL tunnels + the tvtunx binary (full removal)\n"
  printf "    ${B}0${X}  cancel\n"
  hr; read -rp "  choose: " c
  if [[ "$c" == 0 || -z "$c" ]]; then echo "  cancelled."; pause; return; fi
  if [[ "$c" == a ]]; then
    read -rp "  type 'yes' to remove EVERYTHING: " a; [[ "$a" == yes ]] || { echo "  cancelled."; pause; return; }
    for it in "${names[@]}"; do
      if [[ "${it%%:*}" == exit ]]; then systemctl disable --now "tvtunx-server@${it#*:}" >/dev/null 2>&1; else systemctl disable --now "tvtunx-client@${it#*:}" >/dev/null 2>&1; fi
    done
    rm -f /etc/systemd/system/tvtunx-server@.service /etc/systemd/system/tvtunx-client@.service
    systemctl daemon-reload
    rm -f "$BIN"; rm -rf "$CFG"; rm -f /etc/sysctl.d/99-tvtunx.conf
    ok "TVtunX fully removed from this server."; pause; return
  fi
  [[ "$c" =~ ^[0-9]+$ ]] && (( c>=1 && c<=${#names[@]} )) || { warn "invalid"; pause; return; }
  local sel="${names[$((c-1))]}" role="${sel%%:*}" name="${sel#*:}"
  if [[ "$role" == exit ]]; then systemctl disable --now "tvtunx-server@${name}" >/dev/null 2>&1; rm -f "$(server_env "$name")"
  else systemctl disable --now "tvtunx-client@${name}" >/dev/null 2>&1; rm -f "$(client_env "$name")"; fi
  systemctl daemon-reload
  ok "tunnel '${name}' removed."
  pause
}

# summary line for the menu header
installed_summary(){
  local s c; s=$(list_instances server | wc -l | tr -d ' '); c=$(list_instances client | wc -l | tr -d ' ')
  [[ "$s" == 0 && "$c" == 0 ]] && { echo "none"; return; }
  echo "${s} exit, ${c} relay"
}

main_menu(){
  while :; do
    clear; banner; echo
    field "public IP" "${PUBIP:-unknown}"
    [[ -n "$COUNTRY" ]] && field "location" "${COUNTRY} (${CC})"
    [[ -n "$GUESS" ]] && field "guessed role" "$([[ "$GUESS" == relay ]] && echo 'relay (inside Iran)' || echo 'exit (abroad)')"
    field "tunnels here" "$(installed_summary)"
    echo; hr
    printf "    ${B}1${X}  Add / reconfigure an ${B}exit tunnel${X}   (abroad)\n"
    printf "    ${B}2${X}  Add / reconfigure a ${B}relay tunnel${X}    (inside Iran)\n"
    printf "    ${B}3${X}  Edit a tunnel\n"
    printf "    ${B}4${X}  Test a tunnel\n"
    printf "    ${B}5${X}  Benchmark a tunnel  ${Y}${B}(run after install to set speed)${X}\n"
    printf "    ${B}6${X}  Show status (all tunnels)\n"
    printf "    ${B}7${X}  Restart a tunnel\n"
    printf "    ${B}8${X}  Live log\n"
    printf "    ${B}9${X}  Uninstall (one tunnel or all)\n"
    printf "    ${B}0${X}  Exit\n"
    hr
    local def=""; [[ "$GUESS" == exit ]] && def="1"; [[ "$GUESS" == relay ]] && def="2"
    if [[ -n "$def" ]]; then read -rp "  choose [${def}]: " ch; ch=${ch:-$def}; else read -rp "  choose: " ch; fi
    case "$ch" in
      1) install_exit ;; 2) install_relay ;; 3) edit_tunnel ;; 4) test_tunnel ;;
      5) bench_tunnel ;; 6) show_status ;; 7) restart_tunnel ;; 8) live_log ;; 9) uninstall ;;
      0) echo; exit 0 ;; *) warn "invalid choice"; sleep 1 ;;
    esac
  done
}

[[ $EUID -eq 0 ]] || { err "please run as root (sudo ./install.sh)"; exit 1; }
clear
banner
printf "\n  ${D}detecting host...${X}\n"
detect_host
main_menu
