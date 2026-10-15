# byebyedpi

**dpi bypass and telegram for the whole device, ios 5 to 16, one deb**

> [!NOTE]
> all devices need a jailbreak.

## devices

- ios 5-6: armv7
- ios 7-11: armv7, arm64
- ios 12-16: arm64

## strategies

- automatic selection, or a strategy of your own
- tls record and tcp segment splitting
- ByeDPI command-line options

settings and supported options: [config](docs/config.md).

## features

- domain lists, included and custom
- strategy checks, even with the vpn on
- telegram through websocket, or a local mtproxy
- dns: the network's, or an address of your own
- quic blocking, so apps use tcp
- auto reconnect
- russian, english
- classic theme, or light and dark
- diagnostics in the app or `byebyectl`
- vpn badge on ios 5-11 with substrate
- byebyetlsfix: tls 1.3 for the apps you list on ios 5-11 with substrate, see [config](docs/config.md)

an upgrade resets the settings of older builds to the defaults once.

## use

open the app, choose a strategy and turn the tunnel on. `auto` tries another strategy when a tls connection gets no answer. a custom strategy retries only when its ByeDPI options include `-A`.

choose a domain list to limit the cuts to those hosts, or leave lists off for all traffic. quic blocking is on by default so youtube uses tcp.

the strategy check counts a tls handshake response as a pass. check the website and playback in the app you use too.

## old ios tls

byebyetlsfix adds tls 1.3 to safari, webkit and troubadour on ios 5-11 with mobilesubstrate. tls 1.2 stays available for servers that need it. certificates are still checked.

prefs: `/var/mobile/Library/Preferences/com.byebyedpi.byebyetlsfix.plist`. add `enabled-<bundle id>` with a boolean `true` to enable another app. restart that app after changing the prefs or upgrading the shim. ios 12 and later use system tls.

the log is `/var/log/byebyetlsfix.log`. `handshake ok: ... [TLSv1.3]` confirms the negotiated version; `gate: active` only means the app is enabled. settings: [config](docs/config.md#byebyetlsfix).

checked on iphone 4s, ios 9.3.6: youtube in troubadour. on ios 6.1.3, a full h.264 video download through cfnetwork with tls 1.3.

while the tunnel is on, `tlsfix.dylib` is saved as `tlsfix.dylib.byebyedpi-disabled` beside the original and byebyetlsfix handles tls. stopping the tunnel restores it. a failed start, daemon restart or package removal restores it too. existing backups are never overwritten. restart apps after switching, loaded tls hooks stay in their processes. `senkotlsfix` still disables byebyetlsfix.

when replacing `tlsfix`, byebyetlsfix serves cfnetwork apps too. an explicit `enabled-<bundle id> = false` still disables it for that app.

## install

repo: `https://sqmrak.github.io/sqmrakdev/`

```bash
scp byebyedpi-*.deb root@<device-ip>:/var/mobile/
ssh root@<device-ip> dpkg -i /var/mobile/byebyedpi-*.deb
```

remove: `dpkg -r com.byebyedpi.daemon`

on ios 5-6, launchctl can list jobs while its unix socket is unavailable. if the job is absent, the installer starts the daemon directly. launchd starts it at the next boot.

## paths

- config: `/var/root/Library/Preferences/byebyedpi.cfg`
- socket: `/var/tmp/byedpid.sock`
- log: `/var/log/byebyedpi-system.log`
- tls log: `/var/log/byebyetlsfix.log`
- host lists: `/var/mobile/Library/Preferences/byebyedpi-hosts/`
- app: `/Applications/ByeByeDPI.app` (rootless: `/var/jb/Applications/ByeByeDPI.app`)

## build

```bash
make test
make deb
```

needs `THEOS BYE_SDK_V7 BYE_SDK_V64 BYE_CRT_V7 BYE_OSSL_V7 BYE_OSSL_V64 BYE_CA_BUNDLE_SRC BYE_MBED`, outputs `byebyedpi-v<version>.deb`.

`BYE_MBED` must hold mbedtls 3.6 libraries with tls 1.3, one set per slice. `BYE_DEB_OUT` changes the output directory. the build runs host tests, signs armv7 and arm64, then checks the archive, permissions, resources and checksums. to check an existing deb:

```bash
./scripts/verify_deb.sh byebyedpi-v1.2.0-stable.deb
```

## license

[gpl v2](LICENSE), see [NOTICE](NOTICE).
