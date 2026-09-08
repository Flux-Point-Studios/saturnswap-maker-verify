#!/usr/bin/env bash
# Every gate that judges maker_stake, in one runnable place.
#
# This is what CI runs — GitHub Actions and Woodpecker both call it and add
# nothing of their own — and it is what a developer runs before pushing. One
# copy, because the alternative is two CI files each carrying its own copy of
# the Aiken checksum, the validator hash pin, and the upstream cardano-swaps
# commit, drifting apart until the pins stop meaning anything.
#
# Everything it fetches is checked against a pinned SHA256 before use. That is
# not ceremony: this script's whole purpose is to say which bytes a client's
# ceremony hash came from.
#
#   ./verify_project.sh          # install the pinned toolchain, run every gate
#
# Downloads and checksums the pinned Aiken release. Python dependencies go to a temp
# directory on PYTHONPATH, never to site-packages — a --require-hashes install
# still runs the package's own build code, and the suites it is installed FOR
# are the ones that judge the validator.
set -euo pipefail

# The base (unapplied) hash the validator source must compile to. A change here
# re-parameterises every client ceremony, so it is pinned rather than trusted.
EXPECTED_BOUND=18d2246d8b552b9e462ec93dece5716a7154314680b3f326a854789d

AIKEN_VERSION=v1.1.22
AIKEN_SHA256=d443f9deab109fd75ae19e22f7dfce4cdd2f70b3f68c152a6a23db6bc1ea76e1

CLI_VERSION=11.0.0.0
CLI_SHA256=c37b26be04106ecd2ba88841e64d3b7ecdc80d838055102323691b087f7255b1

# fallen-icarus/cardano-swaps: the PUBLIC repo a client rebuilds the spend
# validator and beacon policy from. Fetched rather than vendored, because
# rebuilding from upstream is the property the escape hatch's refusals rest on.
CARDANO_SWAPS_COMMIT=520ea1d27d5fdee36f7f461e725aaf2be05e79f4
CARDANO_SWAPS_SHA256=01f38a96c0c8b0b7c57c65393ba3f69a8de912bbfe2b99e6154afeeba1e96320

cd "$(dirname "${BASH_SOURCE[0]}")"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

gate(){ printf '\n\033[1m== %s\033[0m\n' "$1"; }

gate "toolchain"
# Always downloaded and checksummed, never taken from PATH. An `aiken` that
# merely reports the right version is not the right compiler: the root project
# next door is byte-sensitive to the BUILD, not just the version string, and a
# pin the script can talk itself out of is not a pin. Installed from the release
# rather than through setup-aiken, which 404s on this version — it asks for a
# -gnu tarball and the project publishes -musl.
tarball=aiken-x86_64-unknown-linux-musl.tar.gz
curl -fsSL -o "$WORK/$tarball" \
  "https://github.com/aiken-lang/aiken/releases/download/$AIKEN_VERSION/$tarball"
echo "$AIKEN_SHA256  $WORK/$tarball" | sha256sum -c -
tar xzf "$WORK/$tarball" -C "$WORK"
export PATH="$WORK/aiken-x86_64-unknown-linux-musl:$PATH"
aiken --version
# verify_ceremony.py rebuilds the project from source in a scratch directory for
# every case, so it must reach the compiler this script just verified — not one
# an inherited AIKEN happens to name.
AIKEN=$(command -v aiken)
export AIKEN

# The fee-channel golden vectors are pinned to this cli's own output, so it is
# the standalone release by checksum. Statically linked: a slim image needs
# nothing else to run it, and it ships mode 0644, hence the install.
if [ "$(cardano-cli --version 2>/dev/null | awk 'NR==1{print $2}')" = "$CLI_VERSION" ]; then
  echo "using $(command -v cardano-cli): cardano-cli $CLI_VERSION"
else
  cli_tar=cardano-cli-$CLI_VERSION-x86_64-linux.tar.gz
  curl -fsSL -o "$WORK/$cli_tar" \
    "https://github.com/IntersectMBO/cardano-cli/releases/download/cardano-cli-$CLI_VERSION/$cli_tar"
  echo "$CLI_SHA256  $WORK/$cli_tar" | sha256sum -c -
  tar xzf "$WORK/$cli_tar" -C "$WORK"
  install -m 0755 "$WORK/cardano-cli-x86_64-linux" "$WORK/cardano-cli"
  export PATH="$WORK:$PATH"
  cardano-cli --version | head -1
fi

gate "aiken fmt / check / build"
aiken fmt --check
aiken check -D
aiken build

# `aiken build` REWRITES plutus.json and regenerates a missing aiken.lock, so
# running it before the verifier would make that suite's committed-artefact
# checks compare a fresh build against a fresh build. The committed blueprint
# has to BE what the source compiles to, and this is where that is asserted.
gate "the committed blueprint is what the source compiles to"
# `git diff` returns 0 for a path git does not track, so it cannot tell "matches
# the build" from "there is nothing committed to compare against" — and the
# build above would have just regenerated both. Fail closed first.
git ls-files --error-unmatch plutus.json aiken.lock >/dev/null
git diff --exit-code -- plutus.json aiken.lock
echo "plutus.json and aiken.lock match the build"

gate "the unapplied validator hash matches the pin"
built=$(python3 - <<'PY'
import json
d = json.load(open('plutus.json'))
# EXACT module.validator prefix, not a substring: a decoy module whose title
# merely CONTAINS this name and sorts earlier would otherwise be what the pin
# checks, leaving the real validator free to change. Every purpose shares one
# compiled script, so they must all agree — anything else means the blueprint
# is not what it claims.
want = 'maker_stake_bound.maker_stake_bound.'
hashes = {v['hash'] for v in d['validators'] if v['title'].startswith(want)}
if len(hashes) != 1:
    raise SystemExit(f'expected exactly one {want}* script, found {hashes or None}')
print(hashes.pop())
PY
)
echo "built:    $built"
echo "expected: $EXPECTED_BOUND"
[ "$built" = "$EXPECTED_BOUND" ] || {
  echo "the validator source changed its applied-parameter surface." >&2
  echo "Every client ceremony derives from this hash, so update the pin" >&2
  echo "DELIBERATELY and re-derive the ceremony verifier's golden vector." >&2
  exit 1
}

gate "python dependencies, pinned by hash"
# The verifier prefers libsodium and falls back to its own implementation, and
# the preference is what carries the small-order rejections, so the vetted path
# is installed rather than skipped past.
# --break-system-packages only where pip has it: a Debian pip refuses to install
# at all without it, and a pip predating it refuses the flag. Nothing is broken
# either way — --target writes to a directory, never to site-packages.
pip_flags=()
python3 -m pip install --help | grep -q -- --break-system-packages && pip_flags=(--break-system-packages)
# --only-binary: requirements-ci.txt pins wheels per interpreter and no sdists.
# Without this an interpreter with no pinned wheel answers by compiling C in an
# image that has no compiler — a slow failure that reads as an infrastructure
# fault. With it, pip says which artifact it wanted and stops.
python3 -m pip install --quiet --require-hashes --only-binary :all: \
  --target "$WORK/pydeps" "${pip_flags[@]}" -r requirements-ci.txt
export PYTHONPATH="$WORK/pydeps${PYTHONPATH:+:$PYTHONPATH}"
python3 -c 'import nacl.signing; print("PyNaCl", nacl.__version__)'

# unittest, not pytest: these tools are stdlib-only because a client has to be
# able to run them, and their suites are held to the same bar.
gate "the ceremony verifier agrees with the built blueprint"
python3 verify_ceremony_test.py

gate "historical generation rebuild and address separation"
python3 verify_generations_test.py

gate "the create-body gate the client witnesses through"
# The one pytest suite: its fixture generates keys, derives a ceremony and builds both
# bodies once for 26 cases. -p no:cacheprovider keeps it from writing .pytest_cache into
# the tree, which the blueprint gate above would then have to ignore.
python3 -m pytest verify_create_body_test.py -q -p no:cacheprovider

gate "the operator fee key"
bash operator_fee_key.test.sh

gate "the fee channel"
# FEE_CHANNEL_REQUIRE_CLI turns a missing cardano-cli into failing golden-vector
# cases instead of a skip, so the real-cli coverage cannot be silently lost.
FEE_CHANNEL_REQUIRE_CLI=1 bash fee_channel.test.sh

gate "the client's escape hatch recovers an address"
curl -fsSL -o "$WORK/cs-plutus.json" \
  "https://raw.githubusercontent.com/fallen-icarus/cardano-swaps/$CARDANO_SWAPS_COMMIT/aiken/plutus.json"
echo "$CARDANO_SWAPS_SHA256  $WORK/cs-plutus.json" | sha256sum -c -
# ESCAPE_REQUIRE_BLUEPRINT turns a missing blueprint into a failure instead of a
# skip. This suite was red for ten cases without anyone noticing, because
# nothing ran it; a skip would be the same silence wearing a green tick.
CS_PLUTUS="$WORK/cs-plutus.json" ESCAPE_REQUIRE_BLUEPRINT=1 bash escape.test.sh

gate "the escape suite fails when its applied-hash pin is wrong"
negative=$(mktemp "$PWD/.escape-negative.XXXXXX.sh")
sed 's/^APPLIED=.*/APPLIED=00000000000000000000000000000000000000000000000000000000/' escape.test.sh > "$negative"
if CS_PLUTUS="$WORK/cs-plutus.json" ESCAPE_REQUIRE_BLUEPRINT=1 bash "$negative" > "$WORK/escape-negative.log" 2>&1; then
  rm -f "$negative"
  echo "escape suite accepted an intentionally incorrect hash pin" >&2
  exit 1
fi
rm -f "$negative"
grep -q 'FAIL bound.plutus really hashes to the applied credential' "$WORK/escape-negative.log"
echo "incorrect pin was rejected by the suite"

printf '\n\033[1;32mall gates passed\033[0m\n'
