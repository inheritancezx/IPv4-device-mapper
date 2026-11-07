#!/usr/bin/env sh
set -eu

project=${1:?usage: ./scripts/reset.sh PROJECT_NAME}
case "$project" in
  wqe7002-[a-z0-9-]*) ;;
  *)
    echo "project name must begin with wqe7002-" >&2
    exit 2
    ;;
esac

echo "This removes containers, volumes and run evidence for Compose project: $project"
printf 'Type the exact project name to continue: '
read -r confirmation
[ "$confirmation" = "$project" ] || { echo "reset cancelled"; exit 1; }

docker compose --project-name "$project" down --volumes --remove-orphans
rm -f evidence/*
touch evidence/.gitkeep
echo "reset complete: $project"
