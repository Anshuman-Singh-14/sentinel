#!/bin/sh
# Create .env from .env.example with a fresh random value for every CHANGE_ME.
#
#   sh scripts/init-env.sh            (macOS, Linux, WSL, Git Bash on Windows)
#
# Refuses to overwrite an existing .env. Values are 48 hex characters from
# /dev/urandom: URL-safe, because the passwords go into connection URLs.
set -eu

cd "$(dirname "$0")/.."
if [ -e .env ]; then
    echo ".env already exists; leaving it alone. Delete it first to regenerate." >&2
    exit 1
fi

secret() {
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

umask 077  # .env holds secrets: readable by you only
: > .env
while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | tr -d '\r')  # tolerate a CRLF checkout
    case "$line" in
        *=CHANGE_ME) printf '%s=%s\n' "${line%=CHANGE_ME}" "$(secret)" >> .env ;;
        *) printf '%s\n' "$line" >> .env ;;
    esac
done < .env.example

echo "Created .env with $(grep -c '=CHANGE_ME$' .env.example) generated secrets."
