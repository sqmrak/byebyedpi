#!/usr/bin/env bash
# legacy dpkg needs deterministic ownership, member order, and checksum paths
set -euo pipefail

DEB="${1:-}"
HOST_AR="${BYE_HOST_AR:-/usr/bin/ar}"
THEOS="${THEOS:-}"
TC="${BYE_TC:-${THEOS:+${THEOS}/toolchain/linux/iphone/bin}}"
if [ -z "${DEB}" ] || [ ! -f "${DEB}" ]; then
  echo "usage: $0 package.deb" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
fail() { echo "$*" >&2; exit 1; }

cp "${DEB}" "${WORK}/pkg.deb"
cd "${WORK}"
"${HOST_AR}" x pkg.deb
for m in debian-binary control.tar.gz data.tar.gz; do
  [ -f "${m}" ] || fail "missing ar member ${m}"
done

# dpkg expects the three archive members in this order
order="$("${HOST_AR}" t pkg.deb | tr '\n' ' ')"
[ "${order}" = "debian-binary control.tar.gz data.tar.gz " ] || fail "bad ar member order: ${order}"
echo "2.0" | cmp -s - debian-binary || fail "debian-binary must be '2.0'"

mkdir control data
tar -xzf control.tar.gz -C control
tar -xzf data.tar.gz -C data
for f in control md5sums postinst postrm prerm; do
  [ -f "control/${f}" ] || fail "control.tar missing ${f}"
done
for f in postinst postrm prerm; do
  [ -x "control/${f}" ] || fail "${f} is not executable in the tar"
  sh -n "control/${f}" || fail "${f} has a syntax error"
done

arch="$(awk -F': ' '$1 == "Architecture" { print $2; exit }' control/control)"
[ "${arch}" = all ] || fail "universal package Architecture must be all, got ${arch:-<empty>}"

# every file lives under /var/jb, nothing in the sealed rootless root
for path in data/*; do
  [ "${path}" = "data/var" ] || fail "the package writes outside /var/jb: ${path}"
done
[ -z "$(find data/var -mindepth 1 -maxdepth 1 ! -name jb)" ] || fail "the package writes beside /var/jb"

[ -x data/var/jb/usr/bin/byedpid ] || fail "daemon payload missing"
[ -x data/var/jb/usr/bin/byebyectl ] || fail "byebyectl payload missing"
[ -f data/var/jb/Library/LaunchDaemons/com.byebyedpi.byedpid.plist ] || fail "launchd plist missing"
[ -x data/var/jb/usr/lib/byebyedpi/status.dylib ] || fail "status hook payload missing"
grep -q 'com.apple.springboard' data/var/jb/usr/lib/byebyedpi/status.plist || fail "status hook filter missing"
grep -q 'byebyedpi-status.dylib' control/postinst || fail "status hook installer missing"
for doc in LICENSE NOTICE tg-ws-proxy-MIT.txt lwip-COPYING mbedtls-LICENSE.txt domain-list-community-MIT.txt; do
  [ -s "data/var/jb/usr/share/doc/byebyedpi/${doc}" ] || fail "license text ${doc} missing"
done
grep -q '<string>/var/jb/usr/bin/byedpid</string>' \
  data/var/jb/Library/LaunchDaemons/com.byebyedpi.byedpid.plist || fail "launchd program path mismatch"
grep -q 'install_rootful_layout' control/postinst || fail "rootful compatibility installer missing"
APP=data/var/jb/Applications/ByeByeDPI.app
[ -x "${APP}/ByeByeDPI" ] || fail "app binary missing"
[ -f "${APP}/Info.plist" ] || fail "app Info.plist missing"
for icon in ByeIcon.png ByeIcon@2x.png ByeIcon-60@2x.png ByeIcon-60@3x.png ByeIcon-72.png ByeIcon-76@2x.png Default.png Default@2x.png Default-568h@2x.png; do
  [ -s "${APP}/${icon}" ] || fail "app resource ${icon} missing"
done
# every launch image the plist names is there at some scale, or ios letterboxes the app on that screen
for name in $(sed -n '/<key>UILaunchImageName<\/key>/{n;s/.*<string>\(.*\)<\/string>.*/\1/p;}' "${APP}/Info.plist" | sort -u); do
  compgen -G "${APP}/${name}*.png" >/dev/null || fail "launch image ${name} is named in Info.plist and missing"
done
grep -q 'UIRequiresFullScreen' "${APP}/Info.plist" || fail "UIRequiresFullScreen is missing from Info.plist"
for glyph in power tune lists speed settings more copy; do
  [ -s "${APP}/ic-${glyph}.png" ] || fail "app glyph ic-${glyph}.png missing"
done
[ "$(ls "${APP}"/list-*.sites | wc -l)" -ge 8 ] || fail "the bundled domain lists are missing"
[ -s "${APP}/LICENSE-MaterialSymbols.txt" ] || fail "the glyph license is missing"
ver="$(sed -n '/<key>CFBundleShortVersionString<\/key>/{n;s/.*<string>\(.*\)<\/string>.*/\1/p;q;}' "${APP}/Info.plist")"
want="$(awk -F': ' '$1 == "Version" { print $2; exit }' control/control)"
[ "${ver}" = "${want}" ] || fail "the app says ${ver}, the package says ${want}"
grep -q 'ByeByeDPI.app' control/postinst || fail "the app installer is missing from postinst"

roots="$(grep -c 'BEGIN CERTIFICATE' data/var/jb/usr/lib/byebyedpi/cacert.pem || true)"
[ "${roots}" -gt 50 ] || fail "the trust roots are missing or too few (${roots})"

# ownership is root, and nothing is writable by others
bad="$(tar -tvzf data.tar.gz | awk '{ split($2, o, "/"); if (o[1] != "0" || o[2] != "0") print }')"
[ -z "${bad}" ] || fail "files not owned by root:root: ${bad}"
if tar -tvzf data.tar.gz | awk '{ print $1 }' | grep -q '^.......w'; then
  fail "a payload file is writable by others"
fi

if [ -n "${TC}" ] && [ -x "${TC}/lipo" ]; then
  for bin in data/var/jb/usr/bin/byedpid data/var/jb/usr/bin/byebyectl; do
    archs="$("${TC}/lipo" -archs "${bin}")"
    [ "${archs}" = "armv7 arm64" ] || fail "${bin} has slices '${archs}', expected 'armv7 arm64'"
    # the runtime may only depend on what every supported ios ships
    for slice in armv7 arm64; do
      "${TC}/lipo" "${bin}" -thin "${slice}" -output "${WORK}/thin"
      deps="$("${TC}/otool" -L "${WORK}/thin" | tail -n +2 | awk '{ print $1 }')"
      unexpected="$(grep -vE '^/usr/lib/libSystem\.B\.dylib$|^/System/Library/Frameworks/(CoreFoundation|SystemConfiguration)\.framework/' <<<"${deps}" || true)"
      [ -z "${unexpected}" ] || fail "${bin} (${slice}) links ${unexpected}"
    done
    # deployment targets: the armv7 slice must run on ios 5
    "${TC}/lipo" "${bin}" -thin armv7 -output "${WORK}/thin"
    "${TC}/otool" -l "${WORK}/thin" | grep -A3 LC_VERSION_MIN_IPHONEOS | grep -q 'version 5\.0' \
      || fail "${bin} armv7 slice does not target ios 5.0"
  done
  # the hook is loaded into springboard, which already holds these libraries
  hook=data/var/jb/usr/lib/byebyedpi/status.dylib
  [ "$("${TC}/lipo" -archs "${hook}")" = "armv7 arm64" ] || fail "${hook} needs armv7 and arm64 slices"
  for slice in armv7 arm64; do
    "${TC}/lipo" "${hook}" -thin "${slice}" -output "${WORK}/thin"
    deps="$("${TC}/otool" -L "${WORK}/thin" | tail -n +3 | awk '{ print $1 }')"
    unexpected="$(grep -vE '^/usr/lib/(libSystem\.B|libobjc\.A)\.dylib$|^/System/Library/Frameworks/(CoreFoundation|Foundation|UIKit)\.framework/' <<<"${deps}" || true)"
    [ -z "${unexpected}" ] || fail "${hook} (${slice}) links ${unexpected}"
  done
  "${TC}/lipo" "${hook}" -thin armv7 -output "${WORK}/thin"
  "${TC}/otool" -l "${WORK}/thin" | grep -A3 LC_VERSION_MIN_IPHONEOS | grep -q 'version 5\.0' \
    || fail "${hook} armv7 slice does not target ios 5.0"

  # the app links the frameworks every supported ios ships, and nothing newer in its armv7 slice
  app="${APP}/ByeByeDPI"
  [ "$("${TC}/lipo" -archs "${app}")" = "armv7 arm64" ] || fail "${app} needs armv7 and arm64 slices"
  for slice in armv7 arm64; do
    "${TC}/lipo" "${app}" -thin "${slice}" -output "${WORK}/thin"
    deps="$("${TC}/otool" -L "${WORK}/thin" | tail -n +2 | awk '{ print $1 }')"
    unexpected="$(grep -vE '^/usr/lib/(libSystem\.B|libobjc\.A)\.dylib$|^/System/Library/Frameworks/(CoreFoundation|CoreGraphics|Foundation|QuartzCore|UIKit)\.framework/' <<<"${deps}" || true)"
    [ -z "${unexpected}" ] || fail "${app} (${slice}) links ${unexpected}"
  done
  "${TC}/lipo" "${app}" -thin armv7 -output "${WORK}/thin"
  "${TC}/otool" -l "${WORK}/thin" | grep -A3 LC_VERSION_MIN_IPHONEOS | grep -q 'version 5\.0' \
    || fail "${app} armv7 slice does not target ios 5.0"
  "${TC}/ldid" -e "${app}" 2>/dev/null | grep -q 'com.apple.private.security.no-sandbox' \
    || fail "${app} lacks the no-sandbox entitlement"
else
  echo "lipo not found, slices not inspected" >&2
fi

(cd data && md5sum -c ../control/md5sums >/dev/null) || fail "md5sums do not match the payload"
echo "deb ok: $(basename "${DEB}")"
