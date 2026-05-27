#!/usr/bin/env bash
# Run sbt on the host, or inside a Docker image when DOCKER_IMAGE is set.
#
# Single entry point for the host-vs-container choice. The musl / glibc / static
# linkage matrix cells become one reproducible command both in CI and locally:
#
#   DOCKER_IMAGE=shuwariafrica/alpine-edge-jdk:17 \
#     KUFULI_STATIC_LINK=true \
#     ./project/scripts/run-sbt.sh "kufuli-native/test"
#
# SBT_PROPS, when set, is split on whitespace and prepended to the sbt argv (for
# matrix-driven -D...=... flags). The container runs --user UID:GID so
# bind-mounted files keep caller ownership; HOME is a per-UID /tmp directory the
# sbt launcher can write to; the Coursier cache is bind-mounted from the host so
# resolution is shared. The repo is mounted at its own host path so target/
# paths stay valid host<->container.
set -euo pipefail

extra_args=()
if [[ -n "${SBT_PROPS:-}" ]]; then
  read -ra extra_args <<< "$SBT_PROPS"
fi

if [[ -z "${DOCKER_IMAGE:-}" ]]; then
  exec sbt "${extra_args[@]}" "$@"
fi

mkdir -p "$HOME/.cache/coursier" "$HOME/.cache/sbt"
container_home="/tmp/kufuli-sbt-$(id -u)"
docker_args=(
  --rm
  --user "$(id -u):$(id -g)"
  -v "$PWD:$PWD"
  -v "$HOME/.cache/coursier:$HOME/.cache/coursier"
  -v "$HOME/.cache/sbt:$HOME/.cache/sbt"
  -w "$PWD"
  -e "HOME=$container_home"
  -e "COURSIER_CACHE=$HOME/.cache/coursier"
  -e "SBT_LOCAL_CACHE=$HOME/.cache/sbt"
)
for env_var in TERM CI SBT_OPTS KUFULI_STATIC_LINK; do
  if [[ -n "${!env_var:-}" ]]; then
    docker_args+=(-e "$env_var")
  fi
done

exec docker run "${docker_args[@]}" --entrypoint sh "$DOCKER_IMAGE" -c \
  'mkdir -p "$HOME" && exec sbt "$@"' \
  sh "${extra_args[@]}" "$@"
