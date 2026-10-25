#!/usr/bin/env bash
# Pull-through registry caches for the docker test containers, so images are downloaded once.
#   tools/test/registry-cache.sh up      start (idempotent) and print the KR_REGISTRY_MIRRORS value
#   tools/test/registry-cache.sh env [NET]  print KR_REGISTRY_MIRRORS (empty if the caches are down);
#                                        with NET, attach the caches to that docker network first
#   tools/test/registry-cache.sh down    stop the caches (the cached blobs are kept)
#   tools/test/registry-cache.sh purge   stop and delete the cached blobs
# One registry:2 proxy per upstream (registry:2 proxies a single remote). Blobs live in named
# docker volumes kr-cache-<name>. Other test scripts pick the mirrors up automatically via `env`.
set -euo pipefail

UPSTREAMS=("k8s registry.k8s.io https://registry.k8s.io" "docker docker.io https://registry-1.docker.io")

NET=${2:-bridge}
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1" 2>/dev/null; }

mirrors() {
  local out=() u name host ip
  for u in "${UPSTREAMS[@]}"; do
    read -r name host _ <<<"$u"
    ip=$(ip_of "kr-cache-$name") || continue
    [ -n "$ip" ] && [ "$(docker inspect -f '{{.State.Running}}' "kr-cache-$name")" = true ] && out+=("$host=http://$ip:5000")
  done
  (IFS=,; echo "${out[*]}")
}

case "${1:-}" in
  up)
    for u in "${UPSTREAMS[@]}"; do
      read -r name _ remote <<<"$u"
      c="kr-cache-$name"
      if docker inspect "$c" >/dev/null 2>&1; then docker start "$c" >/dev/null; continue; fi
      docker run -d --name "$c" --restart unless-stopped -v "$c:/var/lib/registry" \
        -e REGISTRY_PROXY_REMOTEURL="$remote" -e REGISTRY_STORAGE_DELETE_ENABLED=true registry:2 >/dev/null
    done
    sleep 1; mirrors ;;
  env)
    if [ "$NET" != bridge ]; then
      for u in "${UPSTREAMS[@]}"; do read -r name _ <<<"$u"; docker network connect "$NET" "kr-cache-$name" >/dev/null 2>&1 || true; done
    fi
    mirrors ;;
  down) for u in "${UPSTREAMS[@]}"; do read -r name _ <<<"$u"; docker stop "kr-cache-$name" >/dev/null 2>&1 || true; done ;;
  purge) for u in "${UPSTREAMS[@]}"; do read -r name _ <<<"$u"; docker rm -f "kr-cache-$name" >/dev/null 2>&1 || true; docker volume rm "kr-cache-$name" >/dev/null 2>&1 || true; done ;;
  *) sed -n 2,8p "$0"; exit 2 ;;
esac
