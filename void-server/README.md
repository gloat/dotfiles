# void-server

The box behind gloat.ing: Void Linux on a 1-core VPS, OpenResty at the front, Cloudflare in front of that, media on R2, an IRC server and a bot keeping watch. Secrets are cut out and marked `<redacted:…>`.

Published by `sync.py` from an allowlist; secrets are replaced with `<redacted:…>` markers.
Browse it on the site: [gloat.ing/#l1](https://gloat.ing/#l1). Last sync: 2026-10-12T20:50:57Z.

## openresty

The web server: TLS, rate limits, NAXSI, the bot filter, and the Lua gate that hands out the media cookie.

| file | what |
|---|---|
| [`openresty/nginx.conf`](openresty/nginx.conf) | the whole server: TLS 1.3, HTTP/3, rate limits, NAXSI, old /void/ paths redirected to R2 🔒 |
| [`openresty/headers.conf`](openresty/headers.conf) | security headers and the CSP (no inline scripts anywhere, so no hashes) |
| [`openresty/cloudflare-realip.conf`](openresty/cloudflare-realip.conf) | real visitor IPs from Cloudflare's ranges (kept current by cf-ips) |
| [`openresty/lua/void_auth.lua`](openresty/lua/void_auth.lua) | /void/login: passphrase in, HttpOnly cookie out 🔒 |
| [`openresty/lua/dashboard.lua`](openresty/lua/dashboard.lua) | /dashboard: a small Lua status page behind basic auth |

## cloudflare worker

media.gloat.ing: serves the R2 library to logged-in visitors, draws fancyindex-style listings, and takes operator uploads into a separate bucket.

| file | what |
|---|---|
| [`worker/wrangler.toml`](worker/wrangler.toml) | buckets, the Durable Object, upload limits 🔒 |
| [`worker/src/index.js`](worker/src/index.js) | router: cookie check, ranges, 304/416, listings, ?download |
| [`worker/src/listing.js`](worker/src/listing.js) | directory pages in nginx fancyindex markup, so the old theme still fits |
| [`worker/src/auth.js`](worker/src/auth.js) | cookie helpers shared by media and /_op/ |
| [`worker/src/op.js`](worker/src/op.js) | /_op/: channel keys, links, multipart uploads, the admin route |
| [`worker/src/ledger.js`](worker/src/ledger.js) | Durable Object (SQLite): rate limits, daily bytes, pause switch, storage hard stop, event queue |
| [`worker/src/filetypes.js`](worker/src/filetypes.js) | checks an upload's first 4 KB against its extension |
| [`worker/tools/optool`](worker/tools/optool) | operator tool: channel keys, review queue, pause/resume, purge |

## voidbot

A small Go bot on the IRC server: posts uploads and library changes, answers !status, and writes the numbers the site's terminal shows.

| file | what |
|---|---|
| [`voidbot/main.go`](voidbot/main.go) | IRC connection, SASL with back-off, poll loop, owner-only commands |
| [`voidbot/report.go`](voidbot/report.go) | events to grouped IRC lines; strips control codes from user text |
| [`voidbot/worker.go`](voidbot/worker.go) | talks to the Worker's admin route |
| [`voidbot/sysinfo.go`](voidbot/sysinfo.go) | load, memory, disk, services, IRC users: sysinfo.json every 30 s |
| [`voidbot/config.go`](voidbot/config.go) | config loading and defaults |
| [`voidbot/report_test.go`](voidbot/report_test.go) | tests: grouping and injection |
| [`voidbot/config.example.json`](voidbot/config.example.json) | config shape (install.sh fills in the secrets) |
| [`voidbot/install.sh`](voidbot/install.sh) | build, system user, config, runit service |
| [`voidbot/sv/run`](voidbot/sv/run) | runit service: drops to its own user |
| [`voidbot/go.mod`](voidbot/go.mod) | one dependency: ergochat/irc-go |

## ops

The chores that keep it running: certificates, Cloudflare's IP list, encrypted backups, log rotation, fail2ban banning at the edge.

| file | what |
|---|---|
| [`ops/cron.daily/backup`](ops/cron.daily/backup) | daily tar + xz + age; only the PC holds the key, so the box can't read its own backups |
| [`ops/cron.daily/cf-ips`](ops/cron.daily/cf-ips) | syncs Cloudflare's ranges into realip, ufw and fail2ban, with sanity checks and rollback |
| [`ops/cron.daily/lego-renew`](ops/cron.daily/lego-renew) | Let's Encrypt renewals over DNS-01 for the web and IRC certs 🔒 |
| [`ops/lego/web-hook`](ops/lego/web-hook) | installs a renewed cert, tests the config, reloads |
| [`ops/logrotate.d/site`](ops/logrotate.d/site) | weekly web/fail2ban logs, monthly IRC log |
| [`ops/fail2ban/jail.local`](ops/fail2ban/jail.local) | jails; web bans go to Cloudflare's firewall, ssh stays on ufw 🔒 |
| [`ops/fail2ban/filter.d/nginx-badstuff.conf`](ops/fail2ban/filter.d/nginx-badstuff.conf) | the probe filter: only failed requests count |

## shell

Where I actually live on the box: fish, micro, btop, fastfetch.

| file | what |
|---|---|
| [`shell/fish/config.fish`](shell/fish/config.fish) | eza, bat, fzf, ps helpers, a few cd shortcuts |
| [`shell/fish/fish_plugins`](shell/fish/fish_plugins) | fisher + tide (the prompt) |
| [`shell/micro/settings.json`](shell/micro/settings.json) | the editor: twilight, softwrap, gofmt on save |
| [`shell/btop/btop.conf`](shell/btop/btop.conf) | btop |
| [`shell/fastfetch/config.jsonc`](shell/fastfetch/config.jsonc) | fastfetch layout: tree keys and Nerd Font icons |
| [`shell/fastfetch/ascii.txt`](shell/fastfetch/ascii.txt) | the logo, in braille |
