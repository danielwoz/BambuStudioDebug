#!/usr/bin/env bash
# Backport the standalone MITM wire-capture tooling onto each supported
# BambuStudio release tag and cut a per-version debug release.
#
# The MITM addition is PURELY ADDITIVE: it only adds files under
# tools/mitm-logging/, docs/MITM_LOGGING.md, docs/RELEASES.md and the
# .github/workflows/release-mitm.yml workflow, plus a gitignore block. It touches
# NO BambuStudio source, so grafting it onto a stock release tag is zero-conflict
# (the paths do not exist on the tag). The 4-line CMakeLists hook on the working
# branch is intentionally OMITTED -- the tools are standalone Python + a C shim
# built by build_redirect.sh and do not need BambuStudio's CMake.
#
# For each supported tag <ver> this:
#   1. creates/resets branch mitm/<ver> from the tag,
#   2. copies the additive fileset from --source (default: mitm-logging),
#   3. appends the MITM gitignore block,
#   4. removes all other .github/workflows/* (so only release-mitm.yml is on the
#      tag tree -- the stock build workflows never run for a debug-* tag push),
#   5. commits, pushes mitm/<ver>, and creates+pushes tag debug-<ver>.
#
# Pushing debug-<ver> fires release-mitm.yml, which publishes a PRERELEASE (the
# default branch's winget/homebrew workflows fire on `release: released`, not on
# a prerelease, so they are not triggered).
#
# LINUX-ONLY tooling. Usage:
#   backport_mitm.sh [--dry-run] [--no-push] [--only <ver>] [--source <ref>]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_REF="mitm-logging"
REMOTE="origin"
DRY_RUN=0
NO_PUSH=0
ONLY=""

SUPPORTED=(
  v02.03.00.70 v02.03.01.51 v02.04.00.70 v02.05.01.58 v02.05.02.51 v02.05.03.62
  v02.06.00.51 v02.06.01.55 v02.07.00.55 v02.07.01.62 v02.08.00.50 v02.08.01.55
)

# Paths that make up the additive graft (relative to repo root).
GRAFT_PATHS=(
  tools/mitm-logging
  docs/MITM_LOGGING.md
  docs/RELEASES.md
  .github/workflows/release-mitm.yml
)

GITIGNORE_MARKER="BambuStudioDebug MITM wire-logging"
read -r -d '' GITIGNORE_BLOCK <<'EOF' || true

# BambuStudioDebug MITM wire-logging: runtime captures contain live tokens and
# personal identifiers -- never commit. Only anonymized fixtures are committed.
/mitm-captures/
mitm-captures/
fixture-skeletons/
tools/mitm-logging/mitm_redirect.so
tools/mitm-logging/relay_cert.pem
tools/mitm-logging/relay_key.pem
__pycache__/
EOF

log() { printf '[backport] %s\n' "$*"; }

usage() { grep '^#' "$0" | sed 's/^# \?//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --no-push) NO_PUSH=1; shift;;
    --only)    ONLY="$2"; shift 2;;
    --source)  SOURCE_REF="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

cd "$REPO_ROOT"

# Verify the source ref actually carries the graft paths (at least the tools).
if ! git rev-parse -q --verify "$SOURCE_REF^{commit}" >/dev/null; then
  echo "source ref '$SOURCE_REF' not found" >&2; exit 1
fi
if ! git ls-tree -r --name-only "$SOURCE_REF" -- tools/mitm-logging | grep -q import_flow.py; then
  echo "source ref '$SOURCE_REF' has no tools/mitm-logging -- wrong ref?" >&2; exit 1
fi

graft_one() {
  local tag="$1"
  local ver="${tag#v}"
  local branch="mitm/${ver}"
  local dtag="debug-${ver}"

  if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    log "SKIP ${tag}: tag not found in repo"
    return 1
  fi

  # Conflict pre-check: the graft paths must NOT already exist on the tag.
  local pre
  pre="$(git ls-tree -r --name-only "$tag" -- tools/mitm-logging docs/MITM_LOGGING.md .github/workflows/release-mitm.yml 2>/dev/null || true)"
  if [[ -n "$pre" ]]; then
    log "WARN ${tag}: graft paths already present on tag (potential conflict):"
    printf '   %s\n' $pre
  else
    log "OK   ${tag}: clean graft (no pre-existing MITM paths)"
  fi

  local wt; wt="$(mktemp -d "/tmp/mitm-backport-${ver}.XXXXXX")"
  git worktree add -f -B "$branch" "$wt" "$tag" >/dev/null 2>&1

  # Copy the additive fileset from the source ref (git archive => tracked files
  # only, so __pycache__ / built .so are never included).
  local existing=()
  for p in "${GRAFT_PATHS[@]}"; do
    if git ls-tree -r --name-only "$SOURCE_REF" -- "$p" | grep -q .; then existing+=("$p"); fi
  done
  git archive "$SOURCE_REF" -- "${existing[@]}" | tar -x -C "$wt"

  # Append the gitignore block if not already present.
  if ! grep -q "$GITIGNORE_MARKER" "$wt/.gitignore" 2>/dev/null; then
    printf '%s\n' "$GITIGNORE_BLOCK" >> "$wt/.gitignore"
  fi

  # Neutralize: keep only release-mitm.yml under .github/workflows so a debug-*
  # tag push cannot fire the stock build workflows carried by the old tag.
  if [[ -d "$wt/.github/workflows" ]]; then
    find "$wt/.github/workflows" -type f ! -name 'release-mitm.yml' -delete
  fi

  git -C "$wt" add -A
  local nstaged; nstaged="$(git -C "$wt" diff --cached --name-only | wc -l | tr -d ' ')"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY  ${tag}: would commit ${nstaged} file change(s) on ${branch}, tag ${dtag}"
    git -C "$wt" diff --cached --stat | sed 's/^/     /' | tail -8
    git worktree remove --force "$wt" >/dev/null 2>&1 || true
    git branch -D "$branch" >/dev/null 2>&1 || true
    return 0
  fi

  git -C "$wt" -c user.name="danielwoz" -c user.email="danielwoz@gmail.com" \
    commit -q -m "Add Linux MITM wire-capture tooling for BambuStudio ${ver}

Additive graft of tools/mitm-logging + docs/MITM_LOGGING.md + the
release-mitm.yml workflow onto the ${tag} release tree (no BambuStudio source
touched). Other CI workflows are stripped so a debug-* tag push only runs the
tooling-release workflow." || log "note: nothing to commit for ${tag} (already grafted)"

  git -C "$wt" tag -f "$dtag" >/dev/null

  if [[ "$NO_PUSH" -eq 0 ]]; then
    git -C "$wt" push -f "$REMOTE" "$branch" >/dev/null 2>&1
    git -C "$wt" push -f "$REMOTE" "$dtag" >/dev/null 2>&1
    log "PUSH ${tag}: ${branch} + ${dtag} pushed"
  else
    log "LOCAL ${tag}: ${branch} + ${dtag} created (not pushed)"
  fi

  git worktree remove --force "$wt" >/dev/null 2>&1 || true
}

targets=("${SUPPORTED[@]}")
if [[ -n "$ONLY" ]]; then
  case "$ONLY" in v*) targets=("$ONLY");; *) targets=("v${ONLY}");; esac
fi

rc=0
for t in "${targets[@]}"; do
  graft_one "$t" || rc=1
done
git worktree prune >/dev/null 2>&1 || true
exit "$rc"
