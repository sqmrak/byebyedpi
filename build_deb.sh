#!/usr/bin/env bash
# one archive prevents users from choosing the wrong jailbreak layout
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
THEOS="${THEOS:?set THEOS to theos root}"
TC="${BYE_TC:-${THEOS}/toolchain/linux/iphone/bin}"
LIPO="${TC}/lipo"
HOST_AR="${BYE_HOST_AR:-/usr/bin/ar}"
HOST_PATH="${BYE_HOST_PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
PKG_VERSION="$(awk -F': ' '$1 == "Version" { print $2; exit }' "${ROOT}/packaging/DEBIAN/control")"
PKG_ARCH="$(awk -F': ' '$1 == "Architecture" { print $2; exit }' "${ROOT}/packaging/DEBIAN/control")"
if [[ ! "${PKG_VERSION}" =~ ^[0-9][0-9A-Za-z.+:~-]*$ ]]; then
  echo "invalid Debian package version: ${PKG_VERSION:-<empty>}" >&2
  exit 1
fi
if [[ "${PKG_ARCH}" != "all" ]]; then
  echo "universal package must use Architecture: all" >&2
  exit 1
fi
OUT="${BYE_DEB_OUT:-${ROOT}}/byebyedpi-v${PKG_VERSION}.deb"
# thin armv7 sdk: a fat dylib remap is flaky on linux aarch64 hosts
SDK_V7="${BYE_SDK_V7:?set BYE_SDK_V7 to the armv7 sdk}"
SDK_V64="${BYE_SDK_V64:?set BYE_SDK_V64 to the arm64 sdk}"
CRT_V7="${BYE_CRT_V7:?set BYE_CRT_V7 to the armv7 startup object}"
OSSL_V7="${BYE_OSSL_V7:?set BYE_OSSL_V7 to the armv7 openssl prefix}"
OSSL_V64="${BYE_OSSL_V64:?set BYE_OSSL_V64 to the arm64 openssl prefix}"
CA_SRC="${BYE_CA_BUNDLE_SRC:?set BYE_CA_BUNDLE_SRC to a pem bundle of trust roots}"
MBED="${BYE_MBED:?set BYE_MBED to the mbedtls static libraries, armv7 and arm64}"
[ -s "${CA_SRC}" ] || { echo "empty or missing ${CA_SRC}" >&2; exit 1; }
STAGE="${ROOT}/.package-stage"
SLICE="${ROOT}/.build-slices"
# /var stays writable on rootless and rootful systems, so one payload can serve both
JBROOT="/var/jb"
PAYLOAD="${STAGE}${JBROOT}"

cleanup_build_outputs() {
  rm -rf "${STAGE}" "${SLICE}" "${ROOT}/daemon/build" "${ROOT}/app/build"
  rm -f "${ROOT}/byebyetlsfix/"byebyetlsfix*.dylib
  env PATH="${HOST_PATH}" make -C "${ROOT}/tests" clean >/dev/null 2>&1 || true
}

# cleanup on failure too because stale slices can contaminate the next package
trap cleanup_build_outputs EXIT

echo "==> host tests"
# keep the system compiler first so host tests are not built with the ios clang
env PATH="${HOST_PATH}" make -C "${ROOT}/tests" test CC="${CC:-/usr/bin/cc}"

rm -rf "${SLICE}"
mkdir -p "${SLICE}/armv7" "${SLICE}/arm64"

echo "==> daemon armv7"
make -C "${ROOT}/daemon" -f Makefile.ios clean
make -C "${ROOT}/daemon" -f Makefile.ios \
  THEOS="${THEOS}" TC="${TC}" LDID="${TC}/ldid" \
  TRIPLE=arm-apple-darwin11 SDK="${SDK_V7}" \
  ARCH="-arch armv7 -miphoneos-version-min=5.0" OSSL="${OSSL_V7}" \
  CRT="${CRT_V7}" IOS_BINDIR=build/ios-armv7 all
cp "${ROOT}/daemon/build/ios-armv7/byedpid" "${ROOT}/daemon/build/ios-armv7/byebyectl" \
   "${SLICE}/armv7/"

echo "==> daemon arm64"
make -C "${ROOT}/daemon" -f Makefile.ios \
  THEOS="${THEOS}" TC="${TC}" LDID="${TC}/ldid" \
  TRIPLE=arm64-apple-darwin SDK="${SDK_V64}" \
  ARCH="-arch arm64 -miphoneos-version-min=7.0" OSSL="${OSSL_V64}" \
  EXTRA_CFLAGS="-DBYE_ROOTLESS=1" IOS_BINDIR=build/ios-arm64 all
cp "${ROOT}/daemon/build/ios-arm64/byedpid" "${ROOT}/daemon/build/ios-arm64/byebyectl" \
   "${SLICE}/arm64/"

# the app is built the same way, one slice at a time
echo "==> app armv7"
make -C "${ROOT}/app" -f Makefile.ios clean
make -C "${ROOT}/app" -f Makefile.ios \
  THEOS="${THEOS}" TC="${TC}" LDID="${TC}/ldid" \
  TRIPLE=arm-apple-darwin11 SDK="${SDK_V7}" \
  ARCH="-arch armv7 -miphoneos-version-min=5.0" IOS_BINDIR=build/ios-armv7 all
cp "${ROOT}/app/build/ios-armv7/ByeByeDPI" "${SLICE}/armv7/ByeByeDPI"

echo "==> app arm64"
make -C "${ROOT}/app" -f Makefile.ios \
  THEOS="${THEOS}" TC="${TC}" LDID="${TC}/ldid" \
  TRIPLE=arm64-apple-darwin SDK="${SDK_V64}" \
  ARCH="-arch arm64 -miphoneos-version-min=7.0" IOS_BINDIR=build/ios-arm64 all
cp "${ROOT}/app/build/ios-arm64/ByeByeDPI" "${SLICE}/arm64/ByeByeDPI"
"${LIPO}" -create "${SLICE}/armv7/ByeByeDPI" "${SLICE}/arm64/ByeByeDPI" -output "${SLICE}/ByeByeDPI"
"${TC}/strip" -x "${SLICE}/ByeByeDPI"
# ios 14 and later confine an unsandboxed bundle in /Applications without this entitlement
"${TC}/ldid" -S"${ROOT}/app/entitlements.plist" "${SLICE}/ByeByeDPI"

# arm64e devices run arm64 executables
for tool in byedpid byebyectl; do
  "${LIPO}" -create "${SLICE}/armv7/${tool}" "${SLICE}/arm64/${tool}" -output "${SLICE}/${tool}"
  "${TC}/strip" -x "${SLICE}/${tool}"
  "${TC}/ldid" -S "${SLICE}/${tool}"
done

# the vpn badge marker of ios 12 and later, so arm64 only
echo "==> tunnel marker arm64"
APPX_SLICE="${SLICE}/ByeTunnel.appex"
mkdir -p "${APPX_SLICE}"
"${TC}/clang" -target arm64-apple-darwin -B "${TC}" \
  -fno-objc-arc -fapplication-extension -Wall -Wextra -O2 \
  -arch arm64 -miphoneos-version-min=12.0 -isysroot "${SDK_V64}" \
  "${ROOT}/app/tunnel/main.m" "${ROOT}/app/tunnel/ByeTunnelProvider.m" \
  -o "${APPX_SLICE}/ByeTunnel" -Wl,-dead_strip \
  -framework Foundation -framework NetworkExtension -lobjc
"${TC}/ldid" -S"${ROOT}/app/tunnel/entitlements.plist" "${APPX_SLICE}/ByeTunnel"
cp "${ROOT}/app/tunnel/Info.plist" "${APPX_SLICE}/Info.plist"

# ios 12 and later get no hook, so the dylib needs no slice newer than arm64
echo "==> status hook armv7"
"${TC}/clang" -target arm-apple-darwin11 -B "${TC}" \
  -fno-objc-arc -Wall -Wextra -O2 -fPIC \
  -arch armv7 -miphoneos-version-min=5.0 -isysroot "${SDK_V7}" \
  "${ROOT}/status/bye_status_hook.m" -o "${SLICE}/status-armv7.dylib" \
  -dynamiclib -Wl,-no_warn_inits -install_name /usr/lib/byebyedpi/status.dylib \
  -framework Foundation -framework UIKit -framework CoreFoundation -lobjc
"${TC}/ldid" -S "${SLICE}/status-armv7.dylib"

echo "==> status hook arm64"
"${TC}/clang" -target arm64-apple-darwin -B "${TC}" \
  -fno-objc-arc -Wall -Wextra -O2 -fPIC \
  -arch arm64 -miphoneos-version-min=7.0 -isysroot "${SDK_V64}" \
  "${ROOT}/status/bye_status_hook.m" -o "${SLICE}/status-arm64.dylib" \
  -dynamiclib -Wl,-no_warn_inits -install_name /usr/lib/byebyedpi/status.dylib \
  -framework Foundation -framework UIKit -framework CoreFoundation -lobjc
"${TC}/ldid" -S "${SLICE}/status-arm64.dylib"
"${LIPO}" -create "${SLICE}/status-armv7.dylib" "${SLICE}/status-arm64.dylib" -output "${SLICE}/status.dylib"
"${TC}/strip" -x "${SLICE}/status.dylib"
"${TC}/ldid" -S "${SLICE}/status.dylib"

echo "==> byebyetlsfix armv7"
make -C "${ROOT}/byebyetlsfix" -f Makefile.ios clean \
  THEOS="${THEOS}" TC="${TC}" LDID="${TC}/ldid" SDK="${SDK_V7}" MBED="${MBED}"
make -C "${ROOT}/byebyetlsfix" -f Makefile.ios \
  THEOS="${THEOS}" TC="${TC}" LDID="${TC}/ldid" \
  TRIPLE=arm-apple-darwin11 SDK="${SDK_V7}" \
  ARCH="-arch armv7 -miphoneos-version-min=5.0" \
  MBED="${MBED}" MBEDLIBS="${MBED}/lib/libmbedtls-armv7.a ${MBED}/lib/libmbedx509-armv7.a ${MBED}/lib/libmbedcrypto-armv7.a" \
  OUT=byebyetlsfix-armv7.dylib
cp "${ROOT}/byebyetlsfix/byebyetlsfix-armv7.dylib" "${SLICE}/"

echo "==> byebyetlsfix arm64"
make -C "${ROOT}/byebyetlsfix" -f Makefile.ios \
  THEOS="${THEOS}" TC="${TC}" LDID="${TC}/ldid" \
  TRIPLE=arm64-apple-darwin SDK="${SDK_V64}" \
  ARCH="-arch arm64 -miphoneos-version-min=7.0" \
  MBED="${MBED}" MBEDLIBS="${MBED}/lib/libmbedtls-arm64.a ${MBED}/lib/libmbedx509-arm64.a ${MBED}/lib/libmbedcrypto-arm64.a" \
  OUT=byebyetlsfix-arm64.dylib
cp "${ROOT}/byebyetlsfix/byebyetlsfix-arm64.dylib" "${SLICE}/"
"${LIPO}" -create "${SLICE}/byebyetlsfix-armv7.dylib" "${SLICE}/byebyetlsfix-arm64.dylib" -output "${SLICE}/byebyetlsfix.dylib"
"${TC}/strip" -x "${SLICE}/byebyetlsfix.dylib"
"${TC}/ldid" -S "${SLICE}/byebyetlsfix.dylib"

echo "==> stage packaging"
rm -rf "${STAGE}"
APP="${PAYLOAD}/Applications/ByeByeDPI.app"
APP_VERSION="$(sed -n '/<key>CFBundleShortVersionString<\/key>/{n;s/.*<string>\(.*\)<\/string>.*/\1/p;q;}' "${ROOT}/app/Info.plist")"
if [[ "${APP_VERSION}" != "${PKG_VERSION}" ]]; then
  echo "app/Info.plist says ${APP_VERSION:-<empty>}, packaging/DEBIAN/control says ${PKG_VERSION}" >&2
  exit 1
fi
mkdir -p "${STAGE}/DEBIAN" "${PAYLOAD}/usr/bin" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/roots" \
         "${PAYLOAD}/usr/share/doc/byebyedpi" "${PAYLOAD}/Library/LaunchDaemons" "${APP}"
cp "${ROOT}/packaging/DEBIAN/"{control,postinst,postrm,prerm} "${STAGE}/DEBIAN/"
cp "${ROOT}/packaging/Library/LaunchDaemons/com.byebyedpi.byedpid.plist" \
   "${PAYLOAD}/Library/LaunchDaemons/"
cp "${SLICE}/byedpid" "${SLICE}/byebyectl" "${PAYLOAD}/usr/bin/"
cp "${SLICE}/ByeByeDPI" "${APP}/ByeByeDPI"
cp "${ROOT}/app/Info.plist" "${APP}/"
cp "${ROOT}/app/icons/"ByeIcon*.png "${ROOT}/app/icons/"Default*.png "${ROOT}/app/icons/"ic-*.png \
   "${ROOT}/app/icons/sqmrak.jpg" "${ROOT}/app/lists/"list-*.sites "${APP}/"
cp "${ROOT}/art/LICENSE-MaterialSymbols.txt" "${APP}/"
mkdir -p "${APP}/PlugIns"
cp -R "${APPX_SLICE}" "${APP}/PlugIns/"
cp "${CA_SRC}" "${PAYLOAD}/usr/lib/byebyedpi/cacert.pem"
cp "${SLICE}/status.dylib" "${PAYLOAD}/usr/lib/byebyedpi/status.dylib"
cp "${ROOT}/status/bye_status.plist" "${PAYLOAD}/usr/lib/byebyedpi/status.plist"
cp "${SLICE}/byebyetlsfix.dylib" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix.dylib"
cp "${ROOT}/byebyetlsfix/byebyetlsfix.plist" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix.plist"
cp "${ROOT}/byebyetlsfix/prefs.plist" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/prefs.plist"
cp "${CA_SRC}" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/cacert.pem"
cp "${ROOT}/byebyetlsfix/roots/"*.pem "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/roots/"
cp "${ROOT}/LICENSE" "${ROOT}/NOTICE" "${PAYLOAD}/usr/share/doc/byebyedpi/"
cp "${ROOT}/licenses/tg-ws-proxy-MIT.txt" "${ROOT}/licenses/mbedtls-LICENSE.txt" "${PAYLOAD}/usr/share/doc/byebyedpi/"
cp "${ROOT}/licenses/domain-list-community-MIT.txt" "${PAYLOAD}/usr/share/doc/byebyedpi/"
cp "${ROOT}/daemon/tun/third_party/lwip/COPYING" "${PAYLOAD}/usr/share/doc/byebyedpi/lwip-COPYING"

# normalized metadata prevents legacy dpkg from rejecting builder ownership
chmod 755 "${PAYLOAD}/usr/bin/byedpid" "${PAYLOAD}/usr/bin/byebyectl"
chmod 755 "${PAYLOAD}/usr/lib/byebyedpi/status.dylib" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix.dylib" "${APP}" "${APP}/ByeByeDPI"
chmod 755 "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/roots"
chmod 644 "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix.plist" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/"*.pem \
          "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/roots/"*.pem "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix/prefs.plist"
find "${APP}" -type f ! -name ByeByeDPI ! -name ByeTunnel -exec chmod 644 {} +
chmod 755 "${APP}/PlugIns/ByeTunnel.appex" "${APP}/PlugIns/ByeTunnel.appex/ByeTunnel"
chmod 644 "${PAYLOAD}/usr/lib/byebyedpi/cacert.pem" "${PAYLOAD}/usr/lib/byebyedpi/status.plist" "${PAYLOAD}/usr/share/doc/byebyedpi/"* \
          "${PAYLOAD}/Library/LaunchDaemons/"*.plist "${STAGE}/DEBIAN/control"
chmod 755 "${STAGE}/DEBIAN/postinst" "${STAGE}/DEBIAN/postrm" "${STAGE}/DEBIAN/prerm"

echo "==> verify executable slices"
for bin in "${PAYLOAD}/usr/bin/byedpid" "${PAYLOAD}/usr/bin/byebyectl" \
           "${PAYLOAD}/usr/lib/byebyedpi/status.dylib" "${PAYLOAD}/usr/lib/byebyedpi/byebyetlsfix.dylib" "${APP}/ByeByeDPI"; do
  archs="$("${LIPO}" -archs "${bin}")"
  echo "${bin}: ${archs}"
  if [[ "${archs}" != "armv7 arm64" ]]; then
    echo "expected armv7 and arm64 executable slices in ${bin}" >&2
    exit 1
  fi
done

echo "==> generate md5sums (data files only, no ./ prefix)"
# checksums run after chmod so they describe the final payload bytes
(
  cd "${STAGE}"
  : > DEBIAN/md5sums
  find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
    | sort -z \
    | while IFS= read -r -d '' rel; do
        md5sum "${rel}" >> DEBIAN/md5sums
      done
  md5sum -c DEBIAN/md5sums >/dev/null
)

echo "==> pack deb (cydia-safe tar/ar)"
# GNU headers remain readable by the oldest supported device dpkg, and fixed
# mtimes make identical payloads reproducible
pack_tar() {
  local out="$1"; shift
  tar --format=gnu --owner=0 --group=0 --numeric-owner \
      --mtime='2020-01-01 00:00:00' --sort=name \
      -cf - "$@" | gzip -9n > "${out}"
}
PACK="$(mktemp -d)"
trap 'rm -rf "${PACK}"; cleanup_build_outputs' EXIT
printf '2.0\n' > "${PACK}/debian-binary"
(cd "${STAGE}/DEBIAN" && pack_tar "${PACK}/control.tar.gz" control md5sums postinst postrm prerm)
(cd "${STAGE}" && pack_tar "${PACK}/data.tar.gz" --exclude=./DEBIAN --exclude=./DEBIAN/* .)
rm -f "${OUT}"
# dpkg requires debian-binary before the control and data members
(
  cd "${PACK}"
  if ! "${HOST_AR}" -rcD "${OUT}" debian-binary control.tar.gz data.tar.gz 2>/dev/null; then
    "${HOST_AR}" -rc "${OUT}" debian-binary control.tar.gz data.tar.gz
  fi
)

echo "==> verify packed deb"
bash "${ROOT}/scripts/verify_deb.sh" "${OUT}"

ls -lh "${OUT}"
echo "done: ${OUT}"
