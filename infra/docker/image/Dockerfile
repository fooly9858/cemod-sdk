# syntax=docker/dockerfile:1.7
#
# Generic build images for cemod-sdk projects, selected via `--target`:
#   builder       devkitPPC + short-wchar-stdlib toolchain, produces the
#                 trusted-native ELF payload (default target).
#   wups-builder  the stock devkitPro toolchain of WUPS_BASE_IMAGE plus a
#                 WUPS (Wii U Plugin System) library built from the project's
#                 own third_party/toolchains/WiiUPluginSystem/, for the WUPS
#                 plugin payload.
#
# The two targets deliberately do NOT share a toolchain. The ELF payload is a
# freestanding cemod that owns its whole process and needs Minecraft's 16-bit
# wchar_t ABI all the way down, so `builder` pins devkitPPC r46.1 and layers
# the from-source short-wchar newlib/libstdc++ (mcwiiu-stdlib) on top. The
# WUPS payload is loaded by Aroma into a host RPX and links the prebuilt
# libwut.a/libwups.a, which are compiled against the devkitPPC of
# WUPS_BASE_IMAGE. Those two newlibs are not interchangeable: struct _reent
# grew between newlib 4.4.0 (r46.1, sizeof 288, deviceData at offset 284) and
# newlib 4.6.0 (sizeof 512, deviceData at offset 508), so a WUPS plugin built
# on the `builder` toolchain has libsysbase's chdir() writing the devoptab
# device at 284 while libwut's __wut_fsa_chdir() reads it back from 508 --
# a null device dereference on the first chdir(). wups-builder therefore
# derives straight from WUPS_BASE_IMAGE and never sees mcwiiu-stdlib or
# mcwiiu-gcc at all.
#
# The default build context MUST be the consuming project's root directory
# (not this SDK directory) so the ARG-selected devkitPPC vendor archive below
# resolves against the project's own infra/docker/vendor/devkitPPC/
# directory, and so wups-builder's WiiUPluginSystem COPY resolves against
# the project's own third_party/toolchains/WiiUPluginSystem/. A second named
# context "sdk" must point at this SDK's infra/docker/image/ directory (the
# directory this Dockerfile itself lives in) so the stdlib build script and
# patch can be copied in without duplicating them into every project.
# compose.yaml wires both contexts up via docker compose's
# `additional_contexts`.
ARG BASE_IMAGE=ghcr.io/wiiu-env/devkitppc:20260225@sha256:472118aa3d2a1ebb62691e9ae18a21d4d8f14238d688d679c30f5973dc9d9f35
ARG WUPS_BASE_IMAGE=ghcr.io/wiiu-env/devkitppc:20260504@sha256:68785e7d75b070b0aea03272b61f36dd2fddfda4f442cdf0e27b168bd36a09fb

FROM ${BASE_IMAGE} AS builder

ARG DEVKITPPC_ARCHIVE=infra/docker/vendor/devkitPPC/devkitPPC-r46.1-1-linux_x86_64.pkg.tar.zst
ARG DEVKITPPC_SHA256=6695ecfe062ede7b041cdcefc8aaaa997fdb0a61d727626197f1089b4ad75b8c

# Use the same vendored native Linux devkitPPC toolchain the project pins.
# The archive checksum is also verified by docker-build.sh before Docker runs.
COPY ${DEVKITPPC_ARCHIVE} /tmp/devkitPPC.pkg.tar.zst
RUN echo "${DEVKITPPC_SHA256}  /tmp/devkitPPC.pkg.tar.zst" | sha256sum -c - \
    && rm -rf /opt/devkitpro/devkitPPC \
    && bsdtar -xf /tmp/devkitPPC.pkg.tar.zst -C / \
    && rm /tmp/devkitPPC.pkg.tar.zst \
    && /opt/devkitpro/devkitPPC/bin/powerpc-eabi-gcc --version | grep '14.2.0'

ENV DEVKITPRO=/opt/devkitpro \
    DEVKITPPC=/opt/devkitpro/devkitPPC \
    PATH=/opt/devkitpro/devkitPPC/bin:${PATH}

COPY --from=sdk build-short-wchar-stdlib.sh gcc-14.2.0-enable-devoptab-chmod.patch /tmp/
RUN --mount=type=cache,target=/var/cache/mcwiiu-stdlib \
    sh /tmp/build-short-wchar-stdlib.sh \
    && rm /tmp/build-short-wchar-stdlib.sh

WORKDIR /project
CMD ["sh", "-c", "sh \"$CEMOD_SDK_ROOT/infra/docker/container/container-build.sh\""]

# elf2rpl/readrpl ship prebuilt in WUPS_BASE_IMAGE already, so there is no
# wut-tools build stage here -- only the WiiUPluginSystem library itself.
# Built in the very image that goes on to compile and link the plugin, so
# libwups.a, libwut.a, libsysbase.a, libc.a and libstdc++.a all come from one
# devkitPro installation.
FROM ${WUPS_BASE_IMAGE} AS wups-builder
WORKDIR /src/WiiUPluginSystem
COPY third_party/toolchains/WiiUPluginSystem/ ./
RUN make clean && make -j"$(nproc)" \
    && mkdir -p /opt/devkitpro/wups \
    && cp -a lib include share /opt/devkitpro/wups/ \
    && rm -rf /src/WiiUPluginSystem

ENV DEVKITPRO=/opt/devkitpro \
    DEVKITPPC=/opt/devkitpro/devkitPPC \
    PATH=/opt/devkitpro/devkitPPC/bin:${PATH}

# The WUPS payload must be built by exactly one C/C++ runtime. Fail the image
# build if either short-wchar prefix ever leaks into this stage.
RUN test ! -e /opt/devkitpro/mcwiiu-stdlib \
    && test ! -e /opt/devkitpro/mcwiiu-gcc \
    && test -f /opt/devkitpro/devkitPPC/base_rules \
    && test -f /opt/devkitpro/wups/share/wups_rules \
    && test -f /opt/devkitpro/wups/lib/libwups.a \
    && test -f /opt/devkitpro/wut/lib/libwut.a \
    && test -x /opt/devkitpro/tools/bin/elf2rpl \
    && test -x /opt/devkitpro/tools/bin/readrpl

WORKDIR /project
CMD ["sh", "-c", "sh \"$CEMOD_SDK_ROOT/infra/docker/container/container-build-wups.sh\""]
