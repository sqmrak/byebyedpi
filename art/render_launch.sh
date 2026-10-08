#!/usr/bin/env bash
# the launch images are one flat color, the leather's, so nothing is shown before the first screen.
# they exist because ios runs an app that lacks an image of the screen's size in a letterboxed
# compatibility mode: every size an iphone or ipad of ios 5 to 16 has gets one
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FFMPEG="${BYE_FFMPEG:-ffmpeg}"
command -v "${FFMPEG}" >/dev/null || { echo "ffmpeg not found, set BYE_FFMPEG" >&2; exit 1; }
COLOR=0x0e1b2d
OUT="${ROOT}/app/icons"
count=0

# name, width in pixels, height in pixels
while read -r name width height; do
    [ -n "${name}" ] || continue
    "${FFMPEG}" -v error -y -f lavfi -i "color=c=${COLOR}:s=${width}x${height}" -frames:v 1 -pix_fmt rgb24 \
        "${OUT}/${name}.png"
    count=$((count + 1))
done <<'LIST'
Default 320 480
Default@2x 640 960
Default-568h@2x 640 1136
Default-667h@2x 750 1334
Default-736h@3x 1242 2208
Default-812h@3x 1125 2436
Default-896h@2x 828 1792
Default-896h@3x 1242 2688
Default-844h@3x 1170 2532
Default-926h@3x 1284 2778
Default-852h@3x 1179 2556
Default-932h@3x 1290 2796
Default-Landscape-667h@2x 1334 750
Default-Landscape-736h@3x 2208 1242
Default-Landscape-812h@3x 2436 1125
Default-Landscape-896h@2x 1792 828
Default-Landscape-896h@3x 2688 1242
Default-Landscape-844h@3x 2532 1170
Default-Landscape-926h@3x 2778 1284
Default-Landscape-852h@3x 2556 1179
Default-Landscape-932h@3x 2796 1290
Default-Portrait 768 1004
Default-Portrait@2x 1536 2008
Default-Landscape 1024 748
Default-Landscape@2x 2048 1496
Default-Portrait-ios7 768 1024
Default-Portrait-ios7@2x 1536 2048
Default-Landscape-ios7 1024 768
Default-Landscape-ios7@2x 2048 1536
Default-Portrait-810x1080@2x 1620 2160
Default-Landscape-1080x810@2x 2160 1620
Default-Portrait-820x1180@2x 1640 2360
Default-Landscape-1180x820@2x 2360 1640
Default-Portrait-834x1112@2x 1668 2224
Default-Landscape-1112x834@2x 2224 1668
Default-Portrait-834x1194@2x 1668 2388
Default-Landscape-1194x834@2x 2388 1668
Default-Portrait-1024x1366@2x 2048 2732
Default-Landscape-1366x1024@2x 2732 2048
Default-Portrait-744x1133@2x 1488 2266
Default-Landscape-1133x744@2x 2266 1488
LIST
echo "rendered ${count} launch images"
