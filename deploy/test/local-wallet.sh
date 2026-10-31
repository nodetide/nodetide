#!/bin/sh
# Run the test wallet on THIS machine against a remote node. The wallet's keys stay here; it only
# makes outbound HTTPS calls to the node, so nothing on the server changes.
#
#   ./local-wallet.sh https://nt-node.example.org [--verifier https://nt-verifier.example.org] [--port 4572]
#
# Email claims are verified by the stack's independent verification service (default: the node's address with
# nt-node replaced by nt-verifier): it emails a code and you type it into the wallet. State (keys,
# attestations) lives in .local-wallet/ (git-ignored); the HTTP password is generated once and printed.
# Open http://localhost:4572 (user: wallet).
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)

NODE="${1:-}"; [ -n "$NODE" ] || { sed -n '2,8p' "$0"; exit 2; }
shift
VERIFIER=""; PORT=4572
while [ $# -gt 0 ]; do
    case "$1" in
        --verifier) VERIFIER="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

STATE=.local-wallet
mkdir -p "$STATE/data"; chmod 700 "$STATE"
if [ ! -d "$STATE/venv" ]; then
    python3 -m venv "$STATE/venv"
    "$STATE/venv/bin/pip" install -q "$ROOT/python"
fi
# On a Mac the wallet's state file is encrypted with a key held in the Keychain.
if [ "$(uname)" = Darwin ]; then
    "$STATE/venv/bin/python" -c 'import keyring' 2>/dev/null || "$STATE/venv/bin/pip" install -q keyring
    export WALLET_KEY_STORE=keychain
fi
if [ ! -f "$STATE/password" ]; then
    python3 -c 'import secrets;print(secrets.token_urlsafe(18))' > "$STATE/password"
    chmod 600 "$STATE/password"
fi

[ -n "$VERIFIER" ] || VERIFIER=$(printf '%s' "$NODE" | sed 's|//nt-node\.|//nt-verifier.|')

echo "wallet:   http://localhost:$PORT   (user: wallet, password: $(cat "$STATE/password"))"
echo "node:     $NODE"
echo "verifier: $VERIFIER"
NODE_URL="$NODE" WALLET_URL="http://localhost:$PORT" VERIFIER_URL="$VERIFIER" \
WALLET_PASSWORD="$(cat "$STATE/password")" DATA_DIR="$PWD/$STATE/data" HOST=127.0.0.1 PORT="$PORT" \
    "$STATE/venv/bin/python" wallet/app.py
