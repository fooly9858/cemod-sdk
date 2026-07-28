#!/bin/sh
# In-container WUPS build driver, shared by every cemod-sdk project that has
# a platforms/wups/Makefile producing a `.wps` (see README.md's WUPS usage
# section). Generic across projects the same way container-build.sh is for
# the ELF path: it never hardcodes a project or target name, instead reading
# CEMOD_PAYLOAD_SOURCE (the project's platforms/wups/<target>.wps path) and
# PACKAGE_PATH from `make print-project-config CEMOD_PAYLOAD_FORMAT=wups`.
set -eu

jobs=${JOBS:-}
if [ -z "$jobs" ]; then
  jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
fi

powerpc-eabi-gcc --version
python3 --version
test -f "$DEVKITPRO/wups/share/wups_rules"
# The WUPS payload links the prebuilt libwut.a/libwups.a, so it must be built
# by the devkitPro C/C++ runtime those were compiled against. The short-wchar
# prefixes belong to the ELF payload only and must not exist in this image.
test ! -e "$DEVKITPRO/mcwiiu-stdlib"
test ! -e "$DEVKITPRO/mcwiiu-gcc"
command -v elf2rpl >/dev/null
command -v readrpl >/dev/null

wps_path=$(make --no-print-directory print-project-config CEMOD_PAYLOAD_FORMAT=wups | sed -n 's/^CEMOD_PAYLOAD_SOURCE=//p')
platform_dir=$(dirname "$wps_path")
target=$(basename "$wps_path" .wps)

if [ "${CEMOD_WUPS_CLEAN_BUILD:-0}" = "1" ]; then
  make -C "$platform_dir" clean
fi
make -j"$jobs" -C "$platform_dir"

test -s "$platform_dir/$target.wps"
test -s "$platform_dir/${target}_dbg.wps"
test -s "$platform_dir/$target.elf"
powerpc-eabi-readelf -h "$platform_dir/$target.elf" >/dev/null
readrpl -i "$platform_dir/$target.wps" >/dev/null

make -j"$jobs" CEMOD_PAYLOAD_FORMAT=wups package
package_path=$(make --no-print-directory print-project-config CEMOD_PAYLOAD_FORMAT=wups | sed -n 's/^PACKAGE_PATH=//p')

output=out/wups
mkdir -p "$output"
cp "$platform_dir/$target.wps" "$output/$target.wps"
cp "$platform_dir/${target}_dbg.wps" "$output/${target}_dbg.wps"
cp "$platform_dir/$target.elf" "$output/$target.elf"
cp "$package_path" "$output/$(basename "$package_path")"
echo "WUPS artifacts: $output"
