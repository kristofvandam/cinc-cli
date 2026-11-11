#!/usr/bin/env bash
#
# generate_goldens.sh regenerates the golden Policyfile.lock.json for every
# fixture in this directory by running REAL `chef install` (chef-cli) against
# it. The committed goldens are the compatibility oracle the resolver tests
# diff against, so they must come from chef, not from cinc.
#
# Each fixture is a directory holding a Policyfile.rb and a cookbooks/ tree. We
# copy the fixture to a scratch dir OUTSIDE any git repository (so chef's
# NullSCM is used and scm_info stays null, keeping the golden portable), run
# chef install there, and copy the resulting lock back into the fixture. A
# fixture with an included/Policyfile.rb gets that policy installed first, so
# its lock (included/Policyfile.lock.json) is there for include_policy.
#
# Requirements: chef-cli on PATH (the repo was developed against chef-cli
# 6.1.34). Run from anywhere, optionally naming the fixtures to regenerate:
#
#     ./cli/policyfile/resolver/testdata/generate_goldens.sh [fixture ...]
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHEF="${CHEF_CLI_BIN:-chef-cli}"
export CHEF_LICENSE="${CHEF_LICENSE:-accept-no-persist}"

if ! command -v "$CHEF" >/dev/null 2>&1; then
  echo "error: chef-cli not found on PATH (set CHEF_CLI_BIN to override)" >&2
  exit 1
fi

echo "Using $($CHEF --version 2>/dev/null | head -1)"

fixtures=("$@")
if [ ${#fixtures[@]} -eq 0 ]; then
  for fixture in "$HERE"/*/; do fixtures+=("$(basename "$fixture")"); done
fi

for name in "${fixtures[@]}"; do
  fixture="$HERE/$name"
  [ -f "$fixture/Policyfile.rb" ] || continue

  scratch="$(mktemp -d "${TMPDIR:-/tmp}/cinc-golden-$name.XXXXXX")"
  # Copy the fixture sources into the non-git scratch, without the golden.
  cp -R "$fixture/." "$scratch/"
  rm -f "$scratch/Policyfile.lock.json"

  echo "==> $name"
  if [ -f "$scratch/included/Policyfile.rb" ]; then
    rm -f "$scratch/included/Policyfile.lock.json"
    if ( cd "$scratch/included" && "$CHEF" install Policyfile.rb >/dev/null 2>"$scratch/err.log" ); then
      cp "$scratch/included/Policyfile.lock.json" "$fixture/included/Policyfile.lock.json"
      echo "    wrote $name/included/Policyfile.lock.json"
    else
      echo "    chef install FAILED for $name/included:" >&2
      sed 's/^/      /' "$scratch/err.log" >&2 || true
    fi
  fi
  if ( cd "$scratch" && "$CHEF" install Policyfile.rb >/dev/null 2>"$scratch/err.log" ); then
    cp "$scratch/Policyfile.lock.json" "$fixture/Policyfile.lock.json"
    echo "    wrote $name/Policyfile.lock.json"
  else
    echo "    chef install FAILED for $name:" >&2
    sed 's/^/      /' "$scratch/err.log" >&2 || true
  fi
  rm -rf "$scratch"
done

echo "Done."
