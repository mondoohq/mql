#!/bin/bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

## Build the provider and bundle it into a single file

set -eo pipefail

REPOROOT=$(git rev-parse --show-toplevel)
PROVIDER_NAME=${1:-}
PROVIDER_PATH=$REPOROOT/providers/$PROVIDER_NAME
PROVIDER_DIST=$PROVIDER_PATH/dist
BUNDLE_DIST=$REPOROOT/dist

# Maximum number of parallel arch builds (default: 1 — serial builds are faster due to reduced CPU/IO contention)
MAX_PARALLEL=${MAX_PARALLEL:-1}

cd $REPOROOT

if [ -z "$PROVIDER_NAME" ]; then
  echo "Please specify a provider name."
  exit 1
fi

# Check if the provider exists
if [ ! -d "$PROVIDER_PATH" ]; then
  echo "The ${PROVIDER_NAME} provider does not exist.  Please create it first."
  exit 1
fi

# Clean up the dist directory
if [ -d "$PROVIDER_DIST" ]; then
  echo "Previous build detected.  Cleaning up the ${PROVIDER_NAME} provider (${PROVIDER_PATH})..."
  rm -rf "$PROVIDER_DIST"
fi

# Create the dist directory
mkdir -p "$PROVIDER_DIST"
mkdir -p "$BUNDLE_DIST"

# Record the starting timestamp
START_TIME=$(date +%s)

# Extract the version from the provider
# Anchor on the Version field. A bare `grep "Version:"` also matches the
# MinVersion entries in the Requires block, which exist on main and not on
# v13. That made PROVIDER_VERSION two lines, and the bundle filename below
# then split into two words, so tar read the second as a file to archive:
#   tar: go.mondoo.com/mql/providers/core_linux_arm.tar.xz: Cannot stat
PROVIDER_VERSION=$(grep -m1 -E '^[[:space:]]*Version:' ${PROVIDER_PATH}/config/config.go | cut -f2 -d\")

# Build the provider
echo "Building the ${PROVIDER_NAME} provider (Version: ${PROVIDER_VERSION})..."

# Build the non-binary files first
echo "  - Generate the plugin..."
cd ${PROVIDER_PATH} && go run gen/main.go .
echo "  - Compile the resources..."
${REPOROOT}/lr go ${PROVIDER_PATH}/resources/${PROVIDER_NAME}.lr --dist ${PROVIDER_DIST}
echo "  - Generate the resource versions..."
${REPOROOT}/lr versions ${PROVIDER_PATH}/resources/${PROVIDER_NAME}.lr

build_bundle(){
  set -eo pipefail
  local GOOS=$1
  local GOARCH=$2
  local GOARM=${3:-}

  # Use a per-arch build directory to avoid file conflicts during parallel builds
  local ARCH_SUFFIX="${GOOS}_${GOARCH}"
  if [ -n "$GOARM" ]; then
    ARCH_SUFFIX="${ARCH_SUFFIX}_v${GOARM}"
  fi
  local ARCH_DIST="${PROVIDER_DIST}/${ARCH_SUFFIX}"
  mkdir -p "$ARCH_DIST"

  echo "Building ${PROVIDER_NAME} for ${GOOS}/${GOARCH}${GOARM:+/v$GOARM} ..."

  local PROVIDER_EXECUTABLE="${PROVIDER_NAME}"
  if [[ "${GOOS}" == "windows" ]]; then
    PROVIDER_EXECUTABLE="${PROVIDER_EXECUTABLE}.exe"
  fi

  # Build the binary into the arch-specific directory.
  #
  # NOTE: the build target must stay the package ("."), not main.go. Go only
  # links rsrc_windows_*.syso when building a package directory; passing an
  # explicit .go file silently drops the version resource and manifest.
  cd ${PROVIDER_PATH} && CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GOARM=${GOARM} go build -tags production -ldflags "-s -w" -o ${ARCH_DIST}/${PROVIDER_EXECUTABLE} .

  if [[ "${GOOS}" == "windows" ]]; then
    ### SIGN THE BINARY
    echo "  - Signing the binary ${ARCH_DIST}/${PROVIDER_EXECUTABLE}..."
    jsign --storetype TRUSTEDSIGNING \
          --keystore "${TSIGN_AZURE_ENDPOINT}" \
          --storepass "${TSIGN_ACCESS_TOKEN}" \
          --alias "${TSIGN_ACCOUNT_NAME}/${TSIGN_CERT_PROFILE_NAME}" "${ARCH_DIST}/${PROVIDER_EXECUTABLE}"
  fi

  # set linux flags that do not work on macos
  local TAR_FLAGS=""
  if uname -s | grep -q 'Linux'; then
    TAR_FLAGS="--owner=0 --group=0 --no-same-owner"
  fi

  # Create the archive, pulling the binary from the arch dir and json files from the common dist dir
  tar -cf ${BUNDLE_DIST}/${PROVIDER_NAME}_${PROVIDER_VERSION}_${GOOS}_${GOARCH}.tar.xz \
    ${TAR_FLAGS} --use-compress-program='xz -9v' \
    -C ${ARCH_DIST} ${PROVIDER_EXECUTABLE} \
    -C ${PROVIDER_DIST} ${PROVIDER_NAME}.json ${PROVIDER_NAME}.resources.json

  # Clean up the arch-specific directory
  rm -rf "$ARCH_DIST"
}

# Define all build targets
BUILDS=(
  "darwin amd64"
  "darwin arm64"
  "linux amd64"
  "linux 386"
  "linux arm64"
  "linux arm 7"
  "linux ppc64le"
  "linux s390x"
  "windows amd64"
  "windows arm64"
)

# A provider may drop build targets its dependencies cannot compile for (for
# example a dependency that assumes a 64-bit int fails to build on 32-bit
# targets). List one "GOOS GOARCH [GOARM]" target per line, matching the entries
# above, in providers/<name>/.build-skip. Blank lines and # comments are ignored.
SKIP_FILE="${PROVIDER_PATH}/.build-skip"
if [ -f "$SKIP_FILE" ]; then
  FILTERED=()
  for build in "${BUILDS[@]}"; do
    keep=1
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%%#*}"
      # Trim leading and trailing whitespace in pure bash (no subshell, no glob
      # expansion of * or ? that xargs would perform).
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      [ -z "$line" ] && continue
      if [ "$build" = "$line" ]; then
        keep=0
        break
      fi
    done < "$SKIP_FILE"
    if [ "$keep" -eq 1 ]; then
      FILTERED+=("$build")
    else
      echo "  - Skipping ${build} for ${PROVIDER_NAME} (listed in .build-skip)"
    fi
  done
  BUILDS=("${FILTERED[@]}")
fi

echo "  - Building ${#BUILDS[@]} architecture targets (max parallel: ${MAX_PARALLEL})..."

# The generated resource objects live in the provider source directory, so drop
# them once every target has been linked rather than leaving them in the tree.
remove_winres() {
  rm -f "${PROVIDER_PATH}"/rsrc_windows_*.syso
}

# On every exit path, not just the expected ones: nothing clears these objects
# at the start of a run, so a leaked one would be linked into the next windows
# build of this provider carrying a stale version. A background build does not
# inherit an EXIT trap, so this cannot fire while another target is linking.
trap remove_winres EXIT

# Windows binaries carry a VERSIONINFO resource and an application manifest.
# Without them the provider .exe reports no CompanyName/ProductName/
# FileDescription, which contributes to heuristic AV/EDR misclassification.
#
# This has to happen before the build loop below rather than inside
# build_bundle: both windows targets share these files, so generating them per
# target would race whenever MAX_PARALLEL > 1.
#
# The template carries only what go-winres does not already default to. Of the
# manifest settings, `dpi-awareness` is the one that is not a default: left out,
# a binary is marked DPI-aware, which is a claim a headless plugin has no
# business making.
for build in "${BUILDS[@]}"; do
  if [[ "${build}" == windows* ]]; then
    echo "  - Generate the Windows version resource..."
    WINRES_JSON="${PROVIDER_DIST}/winres.json"
    sed "s|__PROVIDER_NAME__|${PROVIDER_NAME}|g" \
      "${REPOROOT}/scripts/winres/provider.json.tmpl" > "${WINRES_JSON}"
    go run github.com/tc-hib/go-winres@v0.3.3 make \
      --in "${WINRES_JSON}" \
      --out "${PROVIDER_PATH}/rsrc" \
      --arch amd64,arm64 \
      --file-version "${PROVIDER_VERSION}" \
      --product-version "${PROVIDER_VERSION}"
    break
  fi
done

# Kill all background build processes on interrupt/termination
cleanup() {
  echo ""
  echo "  Interrupted. Killing background builds..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null
  exit 130
}
trap cleanup INT TERM

# Run builds in parallel with a concurrency limit
PIDS=()
FAILED=0
RUNNING=0

for build in "${BUILDS[@]}"; do
  # If we've hit the parallelism limit, wait for one to finish before launching the next
  if [ $RUNNING -ge $MAX_PARALLEL ]; then
    # Wait for the oldest job
    wait "${PIDS[0]}" || FAILED=1
    PIDS=("${PIDS[@]:1}")
    RUNNING=$((RUNNING - 1))
  fi

  build_bundle $build &
  PIDS+=($!)
  RUNNING=$((RUNNING + 1))
done

# Wait for all remaining builds
for pid in "${PIDS[@]}"; do
  wait "$pid" || FAILED=1
done

if [ $FAILED -ne 0 ]; then
  echo "One or more architecture builds failed."
  exit 1
fi

# Copy schema files to bundle dist for publishing
echo "  - Copying schema files..."
cp ${PROVIDER_DIST}/${PROVIDER_NAME}.resources.json ${BUNDLE_DIST}/${PROVIDER_NAME}_${PROVIDER_VERSION}_schema.json
cp ${PROVIDER_DIST}/${PROVIDER_NAME}.json ${BUNDLE_DIST}/${PROVIDER_NAME}_${PROVIDER_VERSION}_provider.json

# Generate SHA256 checksums
echo "  - Generating SHA256 checksums..."
cd $BUNDLE_DIST
shasum -a 256 ${PROVIDER_NAME}_${PROVIDER_VERSION}_*.xz ${PROVIDER_NAME}_${PROVIDER_VERSION}_schema.json ${PROVIDER_NAME}_${PROVIDER_VERSION}_provider.json > ${PROVIDER_NAME}_${PROVIDER_VERSION}_SHA256SUMS

printf "\n\n"
echo "  The ${PROVIDER_NAME} provider has been built and bundled successfully."
echo "  The bundles can be found in ${BUNDLE_DIST}."
echo "  Time Elapsed: $((($(date +%s)-$START_TIME)/60)) minutes"
echo "-------------------------------------------------------"
echo ""
