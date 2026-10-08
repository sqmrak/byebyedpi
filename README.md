# byebyedpi

<p align="center"><b>dpi bypass and telegram for the whole device, ios 5 to 16, one deb</b></p>

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
- dns: `1.1.1.1` by default
- quic blocking, so apps use tcp
- auto reconnect
- russian, english
- diagnostics in the app or `byebyectl`
- vpn badge on ios 5-11 with substrate

older `dns = system` settings use `1.1.1.1` after the upgrade.

## install

repo: `https://sqmrak.github.io/sqmrakdev/`

```bash
scp byebyedpi-*.deb root@<device-ip>:/var/mobile/
ssh root@<device-ip> dpkg -i /var/mobile/byebyedpi-*.deb
```

remove: `dpkg -r com.byebyedpi.daemon`

## paths

- config: `/var/root/Library/Preferences/byebyedpi.cfg`
- socket: `/var/tmp/byedpid.sock`
- log: `/var/log/byebyedpi-system.log`
- host lists: `/var/mobile/Library/Preferences/byebyedpi-hosts/`
- app: `/Applications/ByeByeDPI.app` (rootless: `/var/jb/Applications/ByeByeDPI.app`)

## build

```bash
make -C tests test
./build_deb.sh
```

needs `THEOS BYE_SDK_V7 BYE_SDK_V64 BYE_CRT_V7 BYE_OSSL_V7 BYE_OSSL_V64 BYE_CA_BUNDLE_SRC`, outputs `byebyedpi-v<version>.deb`.

## license

[gpl v2](LICENSE), see [NOTICE](NOTICE).
