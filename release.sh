#!/usr/bin/env bash
# Build and push ndr-engine and/or ndr-ui images to GHCR, then bump VERSION.
# Usage:
#   ./release.sh 1.1.0          — build all three, tag as 1.1.0
#   ./release.sh 1.1.0 engine   — ndr-engine only
#   ./release.sh 1.1.0 auth     — provigil-auth only
#   ./release.sh 1.1.0 ui       — ndr-ui only
set -euo pipefail

REGISTRY="ghcr.io/jithinjoseph-workspace"
NEW_VERSION="${1:-}"
TARGET="${2:-all}"

log()  { printf '\033[0;34m[release]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[  ok  ]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[ fail ]\033[0m %s\n' "$*" >&2; exit 1; }

[ -z "$NEW_VERSION" ] && die "Usage: ./release.sh <version> [engine|ui|all]"

cd "$(dirname "$0")"

# ── Auth ───────────────────────────────────────────────────────────────────────
if [ -z "${GITHUB_TOKEN:-}" ]; then
    if command -v gh &>/dev/null && gh auth status &>/dev/null; then
        GITHUB_TOKEN=$(gh auth token)
    else
        die "Set GITHUB_TOKEN or run 'gh auth login' first"
    fi
fi
echo "$GITHUB_TOKEN" | docker login ghcr.io -u jithinjoseph-workspace --password-stdin
ok "Authenticated to ghcr.io"

# ── Bump version in Cargo.toml and VERSION file ───────────────────────────────
log "Bumping version → $NEW_VERSION"
sed -i "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" \
    rust/ndr-engine/Cargo.toml \
    rust/auth-service/Cargo.toml \
    rust/provigil-common/Cargo.toml
printf '%s\n' "$NEW_VERSION" > VERSION
ok "VERSION file and Cargo.toml files updated"

build_engine() {
    log "Building ndr-engine:${NEW_VERSION}..."
    docker build \
        --build-arg CACHEBUST="$(date +%s)" \
        -t "${REGISTRY}/ndr-engine:${NEW_VERSION}" \
        -t "${REGISTRY}/ndr-engine:latest" \
        -f rust/Dockerfile \
        ./rust
    docker push "${REGISTRY}/ndr-engine:${NEW_VERSION}"
    docker push "${REGISTRY}/ndr-engine:latest"
    ok "ndr-engine pushed → :${NEW_VERSION} and :latest"
}

build_auth() {
    log "Building provigil-auth:${NEW_VERSION}..."
    docker build \
        -t "${REGISTRY}/provigil-auth:${NEW_VERSION}" \
        -t "${REGISTRY}/provigil-auth:latest" \
        -f rust/auth-service/Dockerfile \
        ./rust
    docker push "${REGISTRY}/provigil-auth:${NEW_VERSION}"
    docker push "${REGISTRY}/provigil-auth:latest"
    ok "provigil-auth pushed → :${NEW_VERSION} and :latest"
}

build_ui() {
    log "Building ndr-ui:${NEW_VERSION}..."
    docker build \
        -t "${REGISTRY}/ndr-ui:${NEW_VERSION}" \
        -t "${REGISTRY}/ndr-ui:latest" \
        ./ndr-ui
    docker push "${REGISTRY}/ndr-ui:${NEW_VERSION}"
    docker push "${REGISTRY}/ndr-ui:latest"
    ok "ndr-ui pushed → :${NEW_VERSION} and :latest"
}

case "$TARGET" in
    engine) build_engine ;;
    auth)   build_auth ;;
    ui)     build_ui ;;
    all)    build_engine; build_auth; build_ui ;;
    *)      die "Unknown target '$TARGET'. Use: engine | auth | ui | all" ;;
esac

# ── Commit version bump ────────────────────────────────────────────────────────
log "Committing version bump..."
git add VERSION rust/ndr-engine/Cargo.toml rust/auth-service/Cargo.toml rust/provigil-common/Cargo.toml
git commit -m "$(cat <<EOF
chore: release v${NEW_VERSION}

Powered by PromaSecure
EOF
)"
git push origin "$(git branch --show-current)"
ok "Version bump committed and pushed"

printf '\n\033[0;32mRelease v%s complete.\033[0m\n' "$NEW_VERSION"
printf 'On-premise customers will see the update notification within 6 hours.\n\n'
