#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 || ${1:-} == -* ]]; then
    printf 'Usage: bash build-docker.sh [local-image-tag]\n' >&2
    exit 2
fi

root=$(dirname -- "${BASH_SOURCE[0]}")
docker build --tag "${1:-mikrotik-exporter:local}" "$root"
