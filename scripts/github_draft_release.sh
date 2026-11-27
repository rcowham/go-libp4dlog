#!/usr/bin/env bash
# Build distribution assets and create or update a GitHub draft release.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/github_draft_release.sh <tag> [--dry-run] [--skip-build]

Builds release assets for log2sql, p4plog2sql, p4locks and p4dpending, then
creates or updates a GitHub draft release with those assets and sql_report.sh.

  <tag>          Release tag in vX.Y.Z form, for example v0.15.6.
  --dry-run      Build and validate assets, but do not call GitHub.
  --skip-build   Reuse existing distribution assets instead of rebuilding.
  -h, --help     Show this help text.

Tracked changes must be committed. Existing assets reused with --skip-build
must have been built from the intended commit and with the intended version.
The SQLite tools' Go modules use the parser version in their own go.mod files.
EOF
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
cd "$repo_root"

tag=""
dry_run=false
skip_build=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) dry_run=true ;;
        --skip-build) skip_build=true ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; fail "Unknown option: $1" ;;
        *)
            [[ -z "$tag" ]] || fail "Only one release tag may be supplied"
            tag="$1"
            ;;
    esac
    shift
done

[[ -n "$tag" ]] || { usage >&2; fail "Release tag is required"; }
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || \
    fail "Release tag must use vX.Y.Z form: $tag"
git diff --quiet || fail "Tracked worktree changes must be committed before releasing"
git diff --cached --quiet || fail "Staged changes must be committed before releasing"

head_commit=$(git rev-parse HEAD)
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    tag_commit=$(git rev-parse "refs/tags/${tag}^{commit}")
    [[ "$tag_commit" == "$head_commit" ]] || fail "Existing tag $tag does not point at HEAD"
fi

release_exists=false
if [[ "$dry_run" == false ]]; then
    command -v gh >/dev/null 2>&1 || fail "GitHub CLI (gh) is required"
    gh auth status --hostname github.com >/dev/null 2>&1 || \
        fail "Authenticate GitHub CLI first with: gh auth login --hostname github.com"

    remote_refs=$(git ls-remote origin) || fail "Unable to inspect origin"
    awk -v commit="$head_commit" '$1 == commit { found = 1 } END { exit !found }' <<< "$remote_refs" || \
        fail "HEAD ($head_commit) is not on origin; push the release commit first"
    remote_tag=$(awk -v ref="refs/tags/$tag" -v peeled="refs/tags/$tag^{}" \
        '$2 == ref { tag = $1 } $2 == peeled { commit = $1 } END { if (commit != "") print commit; else print tag }' <<< "$remote_refs")
    [[ -z "$remote_tag" || "$remote_tag" == "$head_commit" ]] || \
        fail "Remote tag $tag does not point at HEAD"

    if release_status=$(gh release view "$tag" --json isDraft --jq '.isDraft' 2>&1); then
        [[ "$release_status" == true ]] || fail "Release $tag already exists and is not a draft"
        release_exists=true
        if [[ -z "$remote_tag" ]]; then
            target=$(gh release view "$tag" --json targetCommitish --jq '.targetCommitish') || \
                fail "Unable to inspect draft release target"
            target_commit=$(awk -v ref="refs/heads/$target" '$2 == ref { print $1 }' <<< "$remote_refs")
            [[ "$target" == "$head_commit" || "$target_commit" == "$head_commit" ]] || \
                fail "Draft release $tag does not target HEAD"
        fi
    elif [[ "$release_status" != *"release not found"* ]]; then
        fail "Unable to inspect release $tag: $release_status"
    fi
fi

if [[ "$skip_build" == false ]]; then
    printf 'Note: SQLite tools build against their go.mod parser dependencies; verify those versions before release.\n' >&2
    for component in log2sql p4plog2sql p4locks p4dpending; do
        make -C "cmd/$component" VERSION="$tag" dist
    done
fi

assets=()
for component in log2sql p4plog2sql p4locks p4dpending; do
    for platform in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64.exe; do
        assets+=("cmd/$component/bin/$component-$platform.gz")
    done
    if [[ "$component" == p4locks || "$component" == p4dpending ]]; then
        assets+=("cmd/$component/bin/$component-windows-arm64.exe.gz")
    fi
done
assets+=("cmd/log2sql/sql_report.sh")

for asset in "${assets[@]}"; do
    [[ -s "$asset" ]] || fail "Missing or empty release asset: $asset"
    if [[ "$asset" == *.gz ]]; then
        gzip -t "$asset" || fail "Invalid gzip release asset: $asset"
    fi
done

printf 'Release assets for %s:\n' "$tag"
printf '  %s\n' "${assets[@]}"
if [[ "$dry_run" == true ]]; then
    printf 'Dry run: GitHub release was not created or updated.\n'
    exit 0
fi

if [[ "$release_exists" == true ]]; then
    gh release upload "$tag" "${assets[@]}" --clobber
else
    gh release create "$tag" "${assets[@]}" --draft --target "$head_commit" \
        --title "$tag" --generate-notes
fi
printf 'Draft release %s is ready for review.\n' "$tag"
