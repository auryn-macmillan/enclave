#!/usr/bin/env bash

set -eu  # Exit immediately if a command exits with a non-zero status

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [[ "$*" != *"--no-prebuild"* ]]; then
    "$THIS_DIR/lib/prebuild.sh"
fi

if [ $# -eq 0 ]; then 
  "$THIS_DIR/persist.sh"
  "$THIS_DIR/base.sh"
  if command -v docker >/dev/null 2>&1; then
    "$THIS_DIR/net.sh"
  else
    echo "Skipping net.sh: docker not found"
  fi
else
  "$THIS_DIR/$1.sh"
fi
