#!/usr/bin/env bash

set -euo pipefail

usage() {
	echo "usage: $0 vN.NN.N" >&2
	exit 1
}

if [[ $# -ne 1 ]]; then
	usage
fi

tag="$1"
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "invalid release tag: $tag" >&2
	echo "expected format: vN.NN.N" >&2
	exit 1
fi

if ! command -v git >/dev/null 2>&1; then
	echo "git is required" >&2
	exit 1
fi

if ! command -v go >/dev/null 2>&1; then
	echo "go is required" >&2
	exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
	echo "perl is required" >&2
	exit 1
fi

if ! command -v git-chglog >/dev/null 2>&1 && ! git chglog --help >/dev/null 2>&1; then
	echo "git chglog is required" >&2
	exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

version="${tag#v}"
release_year="$(LC_ALL=C date -u +%Y)"
release_month_short="$(LC_ALL=C date -u +%b | tr '[:upper:]' '[:lower:]')"

readme_path="README.md"
citation_path="docs/CITATION.bib"
docgo_path="doc.go"
changelog_path="CHANGELOG.md"

for path in "$readme_path" "$citation_path" "$docgo_path"; do
	if [[ ! -f "$path" ]]; then
		echo "missing expected file: $path" >&2
		exit 1
	fi
done

export TAG="$tag"
export VERSION="$version"
export RELEASE_YEAR="$release_year"
export RELEASE_MONTH_SHORT="$release_month_short"

perl -0pi -e '
	my $count = 0;
	$count += s/\@software\{gnark-v[0-9]+\.[0-9]+\.[0-9]+,/\@software{gnark-$ENV{TAG},/g;
	$count += s/title        = \{Consensys\/gnark: v[0-9]+\.[0-9]+\.[0-9]+\},/title        = {Consensys\/gnark: $ENV{TAG}},/g;
	$count += s/month        = [a-z]{3},/month        = $ENV{RELEASE_MONTH_SHORT},/g;
	$count += s/year         = [0-9]{4},/year         = $ENV{RELEASE_YEAR},/g;
	$count += s/version      = \{v[0-9]+\.[0-9]+\.[0-9]+\},/version      = {$ENV{TAG}},/g;
	die "unexpected citation replacements in README.md: $count\n" unless $count == 5;
' "$readme_path"

perl -0pi -e '
	my $count = 0;
	$count += s/\@software\{gnark-v[0-9]+\.[0-9]+\.[0-9]+,/\@software{gnark-$ENV{TAG},/g;
	$count += s/title        = \{Consensys\/gnark: v[0-9]+\.[0-9]+\.[0-9]+\},/title        = {Consensys\/gnark: $ENV{TAG}},/g;
	$count += s/month        = [a-z]{3},/month        = $ENV{RELEASE_MONTH_SHORT},/g;
	$count += s/year         = [0-9]{4},/year         = $ENV{RELEASE_YEAR},/g;
	$count += s/version      = \{v[0-9]+\.[0-9]+\.[0-9]+\},/version      = {$ENV{TAG}},/g;
	die "unexpected citation replacements in docs/CITATION.bib: $count\n" unless $count == 5;
' "$citation_path"

perl -0pi -e '
	my $count = s/semver\.MustParse\("[0-9]+\.[0-9]+\.[0-9]+"\)/semver.MustParse("$ENV{VERSION}")/g;
	die "unexpected doc.go replacements: $count\n" unless $count == 1;
' "$docgo_path"

git chglog --next-tag "$tag" --sort semver --output "$changelog_path" "..$tag"
go mod tidy

cat <<EOF
Release preparation updated for $tag.

Updated:
- $readme_path citation block
- $citation_path
- $docgo_path
- $changelog_path via git chglog
- go.mod / go.sum via go mod tidy

Manual follow-up:
- review and update dependency versions deliberately before cutting the release
- inspect the generated changelog and tidy diff before opening or merging the release PR
EOF
