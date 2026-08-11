#!/usr/bin/env bash
set -euo pipefail

SPEC_SHA=e426f93e9682bf53952f15b1803f426be5c57fa0
RUST_SOURCE_SHA=d3cc50049320445ac49eda2b85b8afb5429434be
SUITE_SHA=f792ce4568c8c3efb3b6a055a1c2ba963dc00c35
TS_SHA=9b899225b304b27adef009083cd9ff3bc98b1f09
NODE_MAJOR=24
PNPM_VERSION=11.10.0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_ROOT="${TMPDIR:-/tmp}/robin-ROB-4-interop"
SUITE_DIR="$WORK_ROOT/didwebvh-test-suite"
TS_DIR="$WORK_ROOT/didwebvh-ts"
ROBIN_PUBLIC="$WORK_ROOT/robin-public.json"
ARTIFACT="${ROB4_INTEROP_ARTIFACT:-$WORK_ROOT/interop-results.json}"

case "$(node --version)" in
  v${NODE_MAJOR}.*) ;;
  *) echo "lifecycle interop requires Node ${NODE_MAJOR}.x" >&2; exit 1 ;;
esac
test "$(corepack pnpm@${PNPM_VERSION} --version)" = "$PNPM_VERSION"
test "$(bun --version)" = "1.3.14"

fetch_exact() {
  local repository="$1"
  local revision="$2"
  local destination="$3"
  if [[ ! -d "$destination/.git" ]]; then
    mkdir -p "$destination"
    git -C "$destination" init --quiet
    git -C "$destination" remote add origin "$repository"
  fi
  git -C "$destination" rev-parse --git-dir >/dev/null
  git -C "$destination" fetch --quiet --depth 1 origin "$revision"
  git -C "$destination" checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$destination" rev-parse HEAD)" = "$revision"
}

mkdir -p "$WORK_ROOT"
fetch_exact https://github.com/decentralized-identity/didwebvh-test-suite.git "$SUITE_SHA" "$SUITE_DIR"
fetch_exact https://github.com/decentralized-identity/didwebvh-ts.git "$TS_SHA" "$TS_DIR"

(cd "$TS_DIR" && bun install --frozen-lockfile && bun run build)
corepack pnpm@${PNPM_VERSION} --dir "$SUITE_DIR" install --frozen-lockfile

ROB4_PUBLIC_EXPORT="$ROBIN_PUBLIC" cargo test --quiet --locked --test stage4 \
  authorized_relationship_lifecycles_select_only_current_role_keys -- --exact

ROB4_REPO_ROOT="$REPO_ROOT" \
ROB4_SUITE_DIR="$SUITE_DIR" \
ROB4_TS_DIR="$TS_DIR" \
ROB4_ROBIN_PUBLIC="$ROBIN_PUBLIC" \
ROB4_INTEROP_ARTIFACT="$ARTIFACT" \
corepack pnpm@${PNPM_VERSION} --dir "$SUITE_DIR" exec tsx "$REPO_ROOT/scripts/rob4_interop.ts"

echo "specification=$SPEC_SHA"
echo "didwebvh_rs_source=$RUST_SOURCE_SHA"
echo "suite=$SUITE_SHA"
echo "independent_ts=$TS_SHA"
echo "node=$(node --version) pnpm=$PNPM_VERSION bun=$(bun --version)"
echo "artifact=$ARTIFACT"
