#!/usr/bin/env bash
set -euo pipefail

SUITE_SHA=f792ce4568c8c3efb3b6a055a1c2ba963dc00c35
TS_SHA=9b899225b304b27adef009083cd9ff3bc98b1f09
NODE_MAJOR=24
PNPM_VERSION=11.10.0
WORK_ROOT="${TMPDIR:-/tmp}/robin-ROB-2-interop"
SUITE_DIR="$WORK_ROOT/didwebvh-test-suite"
TS_DIR="$WORK_ROOT/didwebvh-ts"

case "$(node --version)" in
  v${NODE_MAJOR}.*) ;;
  *) echo "interop requires Node ${NODE_MAJOR}.x" >&2; exit 1 ;;
esac

fetch_exact() {
  local repository="$1"
  local revision="$2"
  local destination="$3"
  if [[ ! -d "$destination/.git" ]]; then
    mkdir -p "$destination"
    git -C "$destination" init --quiet
    git -C "$destination" remote add origin "$repository"
  fi
  git -C "$destination" fetch --quiet --depth 1 origin "$revision"
  git -C "$destination" checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$destination" rev-parse HEAD)" = "$revision"
}

mkdir -p "$WORK_ROOT"
fetch_exact https://github.com/decentralized-identity/didwebvh-test-suite.git "$SUITE_SHA" "$SUITE_DIR"
fetch_exact https://github.com/decentralized-identity/didwebvh-ts.git "$TS_SHA" "$TS_DIR"

(cd "$TS_DIR" && bun install --frozen-lockfile && bun run build)
corepack pnpm@${PNPM_VERSION} --dir "$SUITE_DIR" install --frozen-lockfile
mkdir -p "$SUITE_DIR/vectors/basic-create/robin"
cargo run --quiet --locked --example export_interop -- log > "$SUITE_DIR/vectors/basic-create/robin/did.jsonl"
cargo run --quiet --locked --example export_interop -- result > "$SUITE_DIR/vectors/basic-create/robin/resolutionResult.json"
corepack pnpm@${PNPM_VERSION} --dir "$SUITE_DIR" run generate -- basic-create

grep -E '\| basic-create \| robin \| (✅ PASS|🔶 DIFF) \|' "$SUITE_DIR/implementations/ts/status.md"
echo "suite=$SUITE_SHA"
echo "independent_ts=$TS_SHA"
echo "node=$(node --version) pnpm=$PNPM_VERSION"
