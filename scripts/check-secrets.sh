#!/bin/bash
set -u
exec python3 "$(dirname "$0")/check-secrets.py" "$@"
