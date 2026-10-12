#!/usr/bin/env bash
# install.sh: build voidbot and install (or update) it as the runit service "voidbot".
# Run it as yourself; it asks for sudo. Safe to run again after a code change:
# it rebuilds, replaces the binary and restarts the service, and never touches
# an existing /etc/voidbot/config.json.
#
#   /usr/local/bin/voidbot          the binary
#   /etc/voidbot/config.json        root:_voidbot 640 (SASL password, channel key, admin token)
#   /var/lib/voidbot/state.json     the event cursor (_voidbot, 700 dir)
#   /var/lib/voidbot-pub/sysinfo.json  public server stats for the site's terminal (755 dir, 644 file)
#   /etc/sv/voidbot                 runit service; logs go to syslog, tag voidbot
#                                   (/var/log/socklog/daemon/current)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

echo "building..."
go build -trimpath -ldflags="-s -w" -o voidbot .

if ! id _voidbot >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --home-dir /var/lib/voidbot --shell /usr/bin/nologin _voidbot
  echo "created user _voidbot"
fi
sudo install -d -o _voidbot -g _voidbot -m 700 /var/lib/voidbot
# the public server stats (sysinfo.go), served by OpenResty as /void/sysinfo: readable by nginx
sudo install -d -o _voidbot -g _voidbot -m 755 /var/lib/voidbot-pub
sudo install -d -o root -g _voidbot -m 750 /etc/voidbot
sudo install -o root -g root -m 755 voidbot /usr/local/bin/voidbot

new_config=""
if ! sudo test -f /etc/voidbot/config.json; then
  token_file="$HOME/.config/void-op/admin-token"
  [ -s "$token_file" ] || { echo "install.sh: no $token_file (run optool init first)" >&2; exit 1; }
  tmp="$(mktemp)"
  python3 - "$token_file" "$tmp" <<'PY'
import json, secrets, sys
cfg = json.load(open("config.example.json"))
cfg["admin_token"] = open(sys.argv[1]).read().strip()
cfg["sasl_password"] = secrets.token_urlsafe(24)
cfg["ops_key"] = secrets.token_hex(6)
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PY
  sudo install -o root -g _voidbot -m 640 "$tmp" /etc/voidbot/config.json
  rm -f "$tmp"
  new_config=1
  echo "wrote /etc/voidbot/config.json"
fi

if [ ! -d /etc/sv/voidbot ]; then
  sudo cp -r sv/voidbot /etc/sv/voidbot
  echo "installed /etc/sv/voidbot (not enabled yet)"
else
  sudo install -m 755 sv/voidbot/run /etc/sv/voidbot/run
  sudo install -m 755 sv/voidbot/log/run /etc/sv/voidbot/log/run
fi

if [ -L /var/service/voidbot ]; then
  sudo sv restart voidbot
  echo "restarted voidbot"
fi

if [ -n "$new_config" ]; then
  pw="$(sudo python3 -c 'import json; print(json.load(open("/etc/voidbot/config.json"))["sasl_password"])')"
  key="$(sudo python3 -c 'import json; print(json.load(open("/etc/voidbot/config.json"))["ops_key"])')"
  cat <<MSG

Next, in your IRC client (logged in as gloat; /oper first):
  /oper admin <your oper password>
  /msg NickServ SAREGISTER voidbot $pw
  /join #ops
  /msg ChanServ REGISTER #ops
  /mode #ops +sk $key
Then start it:
  sudo ln -s /etc/sv/voidbot /var/service/
  sudo tail -f /var/log/socklog/daemon/current | grep voidbot
MSG
fi
