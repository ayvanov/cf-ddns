#!/bin/sh
set -eu

# Cloudflare DDNS installer for OpenWrt (interactive, safe for curl|sh)
# It reads user input from /dev/tty so it works when piped.

TTY="/dev/tty"

say() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "Run as root"; }
have() { command -v "$1" >/dev/null 2>&1; }

ask() {
  # ask "Prompt" "default"
  prompt="$1"; def="${2:-}"
  if [ -n "$def" ]; then
    printf "%s [%s]: " "$prompt" "$def" >"$TTY"
  else
    printf "%s: " "$prompt" >"$TTY"
  fi
  IFS= read -r ans <"$TTY" || true
  if [ -z "${ans:-}" ]; then
    echo "$def"
  else
    echo "$ans"
  fi
}

ask_yn() {
  # ask_yn "Prompt" "y"|"n"  -> outputs y/n
  prompt="$1"; def="$2"
  while true; do
    ans="$(ask "$prompt (y/n)" "$def")"
    case "$ans" in
      y|Y) echo "y"; return 0 ;;
      n|N) echo "n"; return 0 ;;
      *) echo "Please answer y or n" >"$TTY" ;;
    esac
  done
}

trim() { echo "$1" | tr -d '\r\n'; }

ensure_pkg() {
  pkg="$1"
  opkg list-installed 2>/dev/null | grep -q "^${pkg} " && return 0
  say "Installing package: $pkg"
  opkg install "$pkg" >/dev/null
}

write_updater() {
  say "Writing updater script: /usr/bin/cf-ddns.sh"
  cat > /usr/bin/cf-ddns.sh <<'EOF'
#!/bin/sh
# Cloudflare DDNS updater for OpenWrt
# Usage: cf-ddns.sh /path/to/config.conf

set -eu

log() { logger -t cf-ddns "$*"; echo "$*"; }
die() { log "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

[ "${1:-}" ] || die "Config path required"
CONF="$1"
[ -r "$CONF" ] || die "Config not readable: $CONF"

# shellcheck disable=SC1090
. "$CONF"

: "${CF_TOKEN_FILE:?CF_TOKEN_FILE required}"
: "${ZONE_NAME:?ZONE_NAME required}"
: "${RECORD_NAME:?RECORD_NAME required}"

PROXIED="${PROXIED:-false}"
TTL="${TTL:-1}"
RECORD_TYPE="${RECORD_TYPE:-auto}"   # auto|A|AAAA|both
IP_SOURCE="${IP_SOURCE:-external}"   # external|interface
IFACE="${IFACE:-wan}"
IPV4_URL="${IPV4_URL:-https://api.ipify.org}"
IPV6_URL="${IPV6_URL:-https://api64.ipify.org}"
DRY_RUN="${DRY_RUN:-0}"

case "$PROXIED" in true|false) : ;; *) die "PROXIED must be true/false";; esac
case "$IP_SOURCE" in external|interface) : ;; *) die "IP_SOURCE invalid";; esac
case "$RECORD_TYPE" in auto|A|AAAA|both) : ;; *) die "RECORD_TYPE invalid";; esac
echo "$DRY_RUN" | grep -Eq '^[01]$' || die "DRY_RUN must be 0 or 1"

need curl
need jsonfilter
need ubus || true

[ -r "$CF_TOKEN_FILE" ] || die "Token file not readable: $CF_TOKEN_FILE"
CF_TOKEN="$(tr -d '\r\n' < "$CF_TOKEN_FILE")"
[ -n "$CF_TOKEN" ] || die "Token empty in: $CF_TOKEN_FILE"

api() {
  method="$1"; path="$2"; data="${3:-}"
  if [ -n "$data" ]; then
    curl -fsS -X "$method" "https://api.cloudflare.com/client/v4$path" \
      -H "Authorization: Bearer $CF_TOKEN" \
      -H "Content-Type: application/json" \
      --data "$data"
  else
    curl -fsS -X "$method" "https://api.cloudflare.com/client/v4$path" \
      -H "Authorization: Bearer $CF_TOKEN" \
      -H "Content-Type: application/json"
  fi
}

get_ip_external_v4() { curl -4 -fsS "$IPV4_URL" | tr -d '\r\n'; }
get_ip_external_v6() { curl -6 -fsS "$IPV6_URL" | tr -d '\r\n' || true; }

get_ip_iface_v4() {
  ubus call network.interface."$IFACE" status 2>/dev/null \
  | jsonfilter -e '@["ipv4-address"][0].address' || true
}

get_ip_iface_v6() {
  ubus call network.interface."$IFACE" status 2>/dev/null \
  | jsonfilter -e '@["ipv6-address"][0].address' || true
}

ZONE_ID="$(api GET "/zones?name=$ZONE_NAME&status=active" | jsonfilter -e '@.result[0].id')"
[ -n "$ZONE_ID" ] || die "Zone not found/active: $ZONE_NAME"

update_record() {
  rtype="$1"
  newip="$2"
  [ -n "$newip" ] || { log "Skip $rtype: empty IP"; return 0; }

  rec_json="$(api GET "/zones/$ZONE_ID/dns_records?type=$rtype&name=$RECORD_NAME")"
  rec_id="$(echo "$rec_json" | jsonfilter -e '@.result[0].id')"
  oldip="$(echo "$rec_json" | jsonfilter -e '@.result[0].content')"

  data="$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s}' \
    "$rtype" "$RECORD_NAME" "$newip" "$TTL" "$PROXIED")"

  if [ -z "$rec_id" ]; then
    log "Creating $rtype $RECORD_NAME -> $newip"
    [ "$DRY_RUN" = "1" ] || api POST "/zones/$ZONE_ID/dns_records" "$data" >/dev/null
    return 0
  fi

  if [ "$oldip" = "$newip" ]; then
    log "No change for $rtype ($oldip)"
    return 0
  fi

  log "Updating $rtype: $oldip -> $newip"
  [ "$DRY_RUN" = "1" ] || api PUT "/zones/$ZONE_ID/dns_records/$rec_id" "$data" >/dev/null
}

IP4=""
IP6=""
if [ "$IP_SOURCE" = "external" ]; then
  IP4="$(get_ip_external_v4)"
  IP6="$(get_ip_external_v6)"
else
  IP4="$(get_ip_iface_v4)"
  IP6="$(get_ip_iface_v6)"
fi

case "$RECORD_TYPE" in
  A)    update_record "A" "$IP4" ;;
  AAAA) update_record "AAAA" "$IP6" ;;
  both)
    update_record "A" "$IP4"
    update_record "AAAA" "$IP6"
    ;;
  auto)
    [ -n "$IP4" ] && update_record "A" "$IP4"
    [ -n "$IP6" ] && update_record "AAAA" "$IP6"
    ;;
esac

exit 0
EOF
  chmod +x /usr/bin/cf-ddns.sh
}

write_config() {
  CONF_PATH="$1"
  TOKEN_PATH="$2"

  say "Writing config: $CONF_PATH"
  cat > "$CONF_PATH" <<EOF
# Cloudflare DDNS config

CF_TOKEN_FILE="$TOKEN_PATH"

ZONE_NAME="$ZONE_NAME"
RECORD_NAME="$RECORD_NAME"

PROXIED=$PROXIED
TTL=1

RECORD_TYPE="$RECORD_TYPE"     # auto|A|AAAA|both
IP_SOURCE="$IP_SOURCE"         # external|interface
IFACE="$IFACE"                 # used if IP_SOURCE=interface

IPV4_URL="$IPV4_URL"
IPV6_URL="$IPV6_URL"

DRY_RUN=0
EOF
  chmod 600 "$CONF_PATH" || true
}

setup_cron() {
  CONF_PATH="$1"
  CRON_MIN="$2"

  say "Configuring cron: every ${CRON_MIN} minute(s)"
  mkdir -p /etc/crontabs
  touch /etc/crontabs/root

  # remove previous cf-ddns entries
  grep -v '/usr/bin/cf-ddns.sh' /etc/crontabs/root > /tmp/root.cron.$$ || true
  mv /tmp/root.cron.$$ /etc/crontabs/root

  echo "*/$CRON_MIN * * * * /usr/bin/cf-ddns.sh $CONF_PATH >/dev/null 2>&1" >> /etc/crontabs/root

  /etc/init.d/cron enable >/dev/null 2>&1 || true
  /etc/init.d/cron restart >/dev/null 2>&1 || /etc/init.d/cron start >/dev/null 2>&1 || true
}

# ---- main ----
need_root

[ -c "$TTY" ] || die "No TTY available. Run from an interactive shell (ssh/console), not from non-interactive context."

say "Updating package lists (opkg update)..."
opkg update >/dev/null

ensure_pkg curl
ensure_pkg ca-bundle
ensure_pkg jsonfilter

say "Interactive setup (Cloudflare DDNS)."

ZONE_NAME="$(trim "$(ask "Cloudflare zone (root domain), e.g. example.com" "")")"
[ -n "$ZONE_NAME" ] || die "ZONE_NAME cannot be empty"

RECORD_NAME="$(trim "$(ask "DNS record (FQDN) to update, e.g. home.example.com" "")")"
[ -n "$RECORD_NAME" ] || die "RECORD_NAME cannot be empty"

# Record type
while true; do
  RECORD_TYPE="$(trim "$(ask "Record type: auto / A / AAAA / both" "auto")")"
  case "$RECORD_TYPE" in auto|A|AAAA|both) break ;; *) echo "Choose: auto, A, AAAA, both" >"$TTY" ;; esac
done

# IP source
while true; do
  IP_SOURCE="$(trim "$(ask "IP source: external / interface" "external")")"
  case "$IP_SOURCE" in external|interface) break ;; *) echo "Choose: external or interface" >"$TTY" ;; esac
done

IFACE="wan"
if [ "$IP_SOURCE" = "interface" ]; then
  IFACE="$(trim "$(ask "OpenWrt interface name (e.g. wan, pppoe-wan, wan6)" "wan")")"
  [ -n "$IFACE" ] || die "IFACE cannot be empty"
fi

# Proxied
ans="$(ask_yn "Enable Cloudflare proxy (orange cloud)?" "n")"
PROXIED=false; [ "$ans" = "y" ] && PROXIED=true

# IP services (optional overrides)
IPV4_URL="$(trim "$(ask "IPv4 external IP URL (empty = default)" "https://api.ipify.org")")"
IPV6_URL="$(trim "$(ask "IPv6 external IP URL (empty = default)" "https://api64.ipify.org")")"

# Cron period
CRON_MIN="$(trim "$(ask "Auto-update period in minutes (1..1440)" "5")")"
echo "$CRON_MIN" | grep -Eq '^[0-9]+$' || die "Cron minutes must be a number"
[ "$CRON_MIN" -ge 1 ] 2>/dev/null || die "Cron minutes must be >= 1"
[ "$CRON_MIN" -le 1440 ] 2>/dev/null || die "Cron minutes must be <= 1440"

# Token
say "Paste Cloudflare API Token (will be stored in /etc/cloudflare.token with chmod 600)"
printf "> " >"$TTY"
IFS= read -r CF_TOKEN <"$TTY" || true
CF_TOKEN="$(trim "${CF_TOKEN:-}")"
[ -n "$CF_TOKEN" ] || die "Token cannot be empty"

TOKEN_PATH="/etc/cloudflare.token"
CONF_PATH="/etc/cf-ddns.conf"

say "Writing token: $TOKEN_PATH"
umask 077
printf "%s\n" "$CF_TOKEN" > "$TOKEN_PATH"
chmod 600 "$TOKEN_PATH"

write_updater
write_config "$CONF_PATH" "$TOKEN_PATH"
setup_cron "$CONF_PATH" "$CRON_MIN"

say "Test run now:"
/usr/bin/cf-ddns.sh "$CONF_PATH" || die "Test failed. Check logs: logread -e cf-ddns"

say "Installed successfully."
say "Manual run:  /usr/bin/cf-ddns.sh $CONF_PATH"
say "Logs:        logread -e cf-ddns"
say "Cron file:   /etc/crontabs/root"
