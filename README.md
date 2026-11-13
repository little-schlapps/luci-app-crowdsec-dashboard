# luci-app-crowdsec-dashboard

A LuCI dashboard for the [CrowdSec](https://www.crowdsec.net/) security engine on OpenWrt.

OpenWrt's existing `luci-app-crowdsec-firewall-bouncer` only edits the bouncer's
settings. This package adds **Status → CrowdSec**, which shows what the engine is
doing, so you no longer need `cscli` for day-to-day checks.

## Pages

| Page | Shows |
|---|---|
| **Overview** | Engine and bouncer state, version, registered bouncers, Central API (community blocklist) connectivity, active decisions by reason and origin, the bouncer's nftables counters, and top and recent dropped sources from the `crowdsec:` firewall log |
| **Alerts** | The last 200 detections: top scenarios, top sources, and a filterable list with country / AS and the decision taken |
| **Decisions** | Local bans with an **Unblock** button, plus a box to **look up**, **ban** (1 h / 4 h / 24 h / 7 d) or **unblock** any address, including ones on the community blocklist |
| **Metrics** | Log sources, parsers, scenarios (buckets), whitelists and installed collections: the same data as `cscli metrics` |

Pages refresh every 30 seconds.

## How it works

There's no extra daemon or open port. The pages call a small rpcd ucode backend
(`luci.crowdsec`) that runs `cscli … -o json` and `nft -j list counters` on demand.

- **Narrow ACL:** read methods (`status`, `metrics`, `alerts`, `decisions`,
  `lookup`, `capi_check`, `blocked_log`) and two write methods (`unblock`, `ban`).
- **Validated input:** addresses must match an IPv4/IPv6 address or range pattern
  before they reach `cscli`. Ban durations come from a fixed list.
- **Bounded replies:** `cscli decisions list --ip X` returns the *whole* alert
  that contains X. For a community-blocklist hit, that is about 15,000 decisions
  (around 3 MB). The backend keeps only rows for the queried address and caps
  every list, so a reply always fits in one ubus message.

## Install (OpenWrt 25.12, apk)

```sh
cd /tmp
wget https://github.com/little-schlapps/luci-app-crowdsec-dashboard/releases/download/v1.0.0/luci-app-crowdsec-dashboard-1.0.0-r1.apk
sha256sum luci-app-crowdsec-dashboard-1.0.0-r1.apk   # compare with the .sha256 asset
apk add --allow-untrusted ./luci-app-crowdsec-dashboard-1.0.0-r1.apk
```

Log out of LuCI and back in to load the new menu entry and permissions.

`--allow-untrusted` is needed because this package isn't signed with an
OpenWrt feed key, so check the checksum first.

## Notes

- **Zero firewall counters are normal.** The bouncer's nftables chains run
  *after* fw4's own input and forward chains. Unsolicited inbound traffic is
  dropped by fw4 first, so it never reaches CrowdSec. The counters only grow
  for new inbound connections that fw4 accepts, such as port forwards or open
  services on WAN.
- **The firewall-log tables need deny logging enabled** in the bouncer
  (`crowdsec.bouncer.deny_log=1`; log prefix `crowdsec: `).
- **"Unparsed" lines in Metrics are mostly expected.** For example, the dropbear
  parser only matches failed logins, so successful logins count as unparsed.

## Build from source

With the OpenWrt SDK (25.12 for apk, 24.10 for ipk):

```sh
cp -r luci-app-crowdsec-dashboard <sdk>/feeds/luci/applications/
cd <sdk>
./scripts/feeds install luci-app-crowdsec-dashboard
make package/luci-app-crowdsec-dashboard/compile
```

The package is architecture-independent (`all`/`noarch`).

## License

Apache-2.0
