#!/bin/sh
# Install the AgentRuntime CLI on macOS or Linux (no sudo, nothing else required).
#
#   curl -fsSL https://github.com/agentruntime-io/agentruntime-cli/releases/latest/download/install.sh | sh
#
# Environment overrides:
#   AGENTRUNTIME_VERSION       pin a release tag (default: latest)
#   AGENTRUNTIME_INSTALL_DIR   install location (default: ~/.local/bin)
#   AGENTRUNTIME_CLI_BASE_URL  alternate release host
set -eu

BASE="${AGENTRUNTIME_CLI_BASE_URL:-https://github.com/agentruntime-io/agentruntime-cli/releases}"
BASE="${BASE%/}"
INSTALL_DIR="${AGENTRUNTIME_INSTALL_DIR:-$HOME/.local/bin}"

fail() { echo "error: $*" >&2; exit 1; }

case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) fail "unsupported OS $(uname -s) (Windows: use install.ps1)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

ASSET="agentruntime_${OS}_${ARCH}.tar.gz"
if [ -n "${AGENTRUNTIME_VERSION:-}" ]; then
  PREFIX="$BASE/download/$AGENTRUNTIME_VERSION"
else
  PREFIX="$BASE/latest/download"
fi

if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO "$2" "$1"; }
else
  fail "need curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "need sha256sum or shasum to verify the download"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $ASSET ..."
dl "$PREFIX/$ASSET" "$TMP/$ASSET"
dl "$PREFIX/checksums.txt" "$TMP/checksums.txt"

EXPECTED="$(awk -v f="$ASSET" '{n=$2; sub(/^\*/,"",n); if (n==f) print $1}' "$TMP/checksums.txt")"
[ -n "$EXPECTED" ] || fail "no checksum listed for $ASSET"
ACTUAL="$(sha "$TMP/$ASSET")"
[ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch for $ASSET (expected $EXPECTED, got $ACTUAL)"

tar -xzf "$TMP/$ASSET" -C "$TMP" agentruntime
mkdir -p "$INSTALL_DIR"
chmod 755 "$TMP/agentruntime"
mv -f "$TMP/agentruntime" "$INSTALL_DIR/agentruntime"
# Short alias; a symlink so it always follows the main binary.
ln -sf agentruntime "$INSTALL_DIR/agent"

echo
"$INSTALL_DIR/agentruntime" version
echo
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"   (put this in ~/.zshrc or ~/.bashrc)"; echo ;;
esac

# Another tool may already own the name "agent" (for example the Cursor CLI).
OTHER="$(command -v agent 2>/dev/null || true)"
case "$OTHER" in
  ""|"$INSTALL_DIR/agent") ;;
  *) echo "warning: another 'agent' command is already on your PATH: $OTHER"
     echo "         'agent' may run that one instead of this CLI, depending on PATH order."
     echo "         'agentruntime' always runs this CLI."
     echo ;;
esac
echo "Next: agentruntime login   (short form: agent login)"
