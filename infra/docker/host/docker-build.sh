#!/bin/sh
# Host-side Docker orchestrator, shared by every cemod-sdk project. Builds
# either the trusted-native ELF payload or, with --wups, the WUPS plugin
# payload -- both from the project's single compose.yaml (the wups-builder
# service is gated behind the "wups" compose profile).
#
# Usage: docker-build.sh [--wups] [--install [Cemu data directory]]
#
# --install installs the .cemod this invocation just built (the
# `-wups`-suffixed one with --wups, the plain one otherwise) -- it never
# touches any other package that might already be sitting in out/dist.
#
# Required environment (normally exported by the project's docker-build.sh
# wrapper, see cemod.mk's `docker-build`/`docker-install` targets for the
# canonical example):
#   PROJECT_ROOT          absolute path to the consuming project (compose context)
#   CEMOD_SDK_ROOT         absolute path to this SDK checkout
#   DEVKITPPC_ARCHIVE     path, relative to PROJECT_ROOT, to the vendored
#                         devkitPPC .pkg.tar.zst (also needed for --wups: the
#                         wups-builder image layers on top of the ELF builder image)
#   DEVKITPPC_SHA256      expected sha256 of that archive
#
# Optional environment:
#   CEMOD_PREBUILD_CHECK  path to an executable run before Docker starts, for
#                         project-specific preflight checks (embedded assets,
#                         submodule status, etc). Skipped if unset.
#   CEMOD_EXTRA_VERIFY    space-separated extra `make` targets run inside the
#                         container before packaging (e.g. verify-cemuextend-sdk).
#                         Only used on the ELF path; ignored with --wups.
set -eu

wups=0
if [ "${1:-}" = "--wups" ]; then
  wups=1
  shift
fi

: "${PROJECT_ROOT:?PROJECT_ROOT must be set}"
: "${CEMOD_SDK_ROOT:?CEMOD_SDK_ROOT must be set}"
: "${DEVKITPPC_ARCHIVE:?DEVKITPPC_ARCHIVE must be set}"
: "${DEVKITPPC_SHA256:?DEVKITPPC_SHA256 must be set}"

cd "$PROJECT_ROOT"

command -v docker >/dev/null 2>&1 || { echo "Docker is required." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose is required." >&2; exit 1; }

if [ -n "${CEMOD_PREBUILD_CHECK:-}" ]; then
  "$CEMOD_PREBUILD_CHECK"
fi

devkit_archive="$PROJECT_ROOT/$DEVKITPPC_ARCHIVE"
if [ ! -f "$devkit_archive" ]; then
  echo "Required devkitPPC archive is missing: $devkit_archive" >&2
  exit 1
fi
if ! echo "$DEVKITPPC_SHA256  $devkit_archive" | sha256sum -c - >/dev/null; then
  echo "Invalid devkitPPC archive checksum: $devkit_archive" >&2
  exit 1
fi

export HOST_UID="$(id -u)"
export HOST_GID="$(id -g)"
export CEMOD_SDK_ROOT
export DEVKITPPC_ARCHIVE
export DEVKITPPC_SHA256

if [ "$wups" = 1 ]; then
  # wups-builder no longer layers on top of `builder`: it uses the stock
  # devkitPro toolchain that libwut/libwups were compiled against, with no
  # short-wchar stdlib. Nothing to build for the ELF image here.
  docker compose --profile wups build wups-builder
  docker compose --profile wups run --rm wups-builder
  suffix="-wups"
else
  export CEMOD_EXTRA_VERIFY="${CEMOD_EXTRA_VERIFY:-}"
  docker compose build builder
  docker compose run --rm builder
  suffix=""
fi

if [ "${1:-}" = "--install" ]; then
  if [ "$#" -gt 2 ]; then
    echo "Usage: $0 [--wups] --install [Cemu data directory]" >&2
    exit 2
  fi
  sh "$CEMOD_SDK_ROOT/infra/docker/host/install-cemu-pack.sh" "$suffix" "${2:-}"
fi
