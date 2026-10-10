# config

`/var/root/Library/Preferences/byebyedpi.cfg`

| key | value | default |
| --- | --- | --- |
| `desync.spec` | `auto`, `none`, `tlsrec=P;split=P,P;oob=P`, or ByeDPI options starting with `-` | `auto` |
| `hosts` | file name in the hosts directory, `none` | `none` |
| `hosts.mode` | `only`, `except` | `only` |
| `telegram` | `on`, `off` | `on` |
| `telegram.pool` | `0` to `2` | `1` |
| `quic` | `block`, `pass` | `block` |
| `dns` | ipv4 address, `system` | `1.1.1.1` |
| `relay` | up to 4 domains, `none` | `pclead.co.uk,lovetrue.co.uk,kartoshka.co.uk` |
| `autostart` | `on`, `off` | `off` |
| `proxy` | `on`, `off` | `off` |
| `proxy.port` | `1` to `65535` | `1082` |
| `proxy.secret` | 32 lowercase hex digits, `auto` | `auto` |

configs below version 4 change `dns = system` to `dns = 1.1.1.1` once. custom addresses are kept. selecting `system` after the upgrade keeps the network resolver.

## control

```bash
byebyectl status
byebyectl start
byebyectl stop
byebyectl restart
byebyectl config
byebyectl reload
byebyectl set desync.spec auto
byebyectl set dns 1.1.1.1
byebyectl set proxy on
byebyectl probe youtube.com discord.com
```

settings that affect the tunnel need a restart after `set`.

## strategies

`auto` tries the next built-in strategy when a tls connection gets no answer. working strategies are remembered for later connections. a custom strategy uses only the retry groups it defines with `-A`.

positions: `N`, `name`, `name+N`, `name-N`, `mid`, `end`.

a tls client hello split across tcp packets is collected before processing, up to one 16384-byte record. an incomplete record passes unchanged after 1500 ms.

older lists separated by `|` keep their first strategy. `set` accepts one strategy.

## ByeDPI options

```bash
byebyectl set desync.spec -d1 -d3+s -s6+s -r1+s -As -d1 -s3+s
```

the text can contain up to 1023 bytes. the app accepts it on the strategy screen.

- `-s -d -o -q`: `offset[:repeats[:skip]][+flags]`, with flags `s h n e m r s`
- other supported options: `-r`, `-M`, `-m`, `-e`, `-K t,h`, `-T`, `-g`
- `-d`: sends a segment with ttl 1 so the kernel retransmits it later
- `-o -q`: send an urgent byte in the same segment
- `-A t,s`: retry after no answer, a reset, or a response that is not a tls handshake
- `-A c` and `-A r`: accepted, but do not trigger a retry
- `-f`: splits like `-s`, without a fake packet
- omitted options: `-S -Y -a -t -n -l -O -Q -H -j -V -R -L -u -B -y`, and proxy options

omitted options are reported in the app and `/var/log/byebyedpi-system.log`. an invalid option rejects the setting.

## host lists

one domain per line, `#` for comments. a domain includes its subdomains. a bad or missing list prevents the tunnel from starting. with a list selected, connections without a detected hostname are not modified.

## byebyetlsfix

ios before 12 offers tls 1.2 at best, and ios 5 only 1.0. byebyetlsfix is a substrate tweak that puts mbedtls with tls 1.3 support under the system tls of the apps listed in `/var/mobile/Library/Preferences/com.byebyedpi.byebyetlsfix.plist`. it hooks the securetransport functions themselves, because ios 9 shared-cache calls bypass import pointer hooks.

- `enabled-<bundle id>`: `true` turns it on for that app. safari, webkit and troubadour are on after the install
- `enableAll`: `true` turns it on for every app that loads uikit
- `tls13`, `drainGuard`, `systemFallback`: `true` by default

an app that was running has to be started again. the log is `/var/log/byebyetlsfix.log`. it needs mobilesubstrate and does nothing on ios 12 and later, which have their own tls 1.3.

`gate: active` only means the app is enabled. `shadow hooks` reports the installed hooks, `shadow ready` reports mbedtls initialization, and `handshake ok` gives the negotiated tls version. with `tls13 = true`, tls 1.2 remains available for servers that need it. a successful strategy check does not prove the app used tls 1.3.

## telegram

the tunnel carries mtproto over `kwsN.web.telegram.org`. when this fails, it tries a direct connection.

the relay domains use `kwsN.<domain>` to reach the same telegram gateway. the domain owner can see connection addresses and timing; messages remain mtproto encrypted. `relay = none` disables these domains.

the local mtproxy listens on `127.0.0.1:1082` by default. enable `proxy`, then add it to telegram from the app's settings. it works with the tunnel on or off.

## diagnostics

the strategy check tries up to four names, once per strategy. a tls handshake response counts as a pass. this does not verify that the website or its videos work.

a name without an ipv4 address is reported as `unresolved`, with the reason in `unresolved.error` and the daemon log. the app marks the check as partial. results cover only names with an address.

`external_interface` is the tunnel's bound interface while its routes are installed. otherwise, it is the interface the kernel reports for `1.1.1.1` with `RTM_GET`. lookup failures appear as `external_interface.error`.

brighton's network link is also a utun. it is accepted when the kernel path matches the interface and router in `State:/Network/Service/dev.brighton.netd/IPv4`. its ipv4-only link gets no ipv6 bypass routes. other active vpn interfaces are rejected.

## additional checks

```bash
make -C tests benchmark
make -C tests probe
```

`benchmark` checks a 500000-byte transfer through a local relay, with acknowledgements batched every 10 ms. it reports elapsed time and cpu time, not internet speed.

`probe` asks telegram datacenter 2 for a resPQ response. it needs network access.
