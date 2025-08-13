#!/bin/bash

export RUST_BACKTRACE=1
export RUST_TEST_THREADS=1

# Parse command line args.
DEST_DIR=""
LIST_TESTS=false
RUN_SPECIFIC_TEST=""
UNPACK_TESTS=false
while getopts ":d:l:t:u" opt; do
  case ${opt} in
    d )
      DEST_DIR="$OPTARG"
      ;;
    l )
      LIST_TESTS=true
      ;;
    t )
      RUN_SPECIFIC_TEST="$OPTARG"
      ;;
    u )
      UNPACK_TESTS=true
      ;;
    \? )
      echo "Invalid option: -$OPTARG" 1>&2
      exit 1
      ;;
  esac
done

# Check destination dir provided.
if [ -z "$DEST_DIR" ]; then
  echo "Usage: ./run-fpga-tests.sh -d <destination dir> -t <test>"
  exit 1
fi

# Unpack the nextest test archive if requested.
if [ "$UNPACK_TESTS" = true ]; then
  cd "${HOME}/${DEST_DIR}"
  tar -xvf caliptra-test-bins.tar.zst
fi

# List / execute tests.
COMMON_ARGS=(
    --cargo-metadata="${HOME}/${DEST_DIR}/target/nextest/cargo-metadata.json"
    --binaries-metadata="${HOME}/${DEST_DIR}/target/nextest/binaries-metadata.json"
    --target-dir-remap="${HOME}/${DEST_DIR}/target"
    --workspace-remap=.
    -E 'package(mcu-hw-model) - test(model_emulated::test::test_new_unbooted)'
)
cd "${HOME}/caliptra-mcu-sw"
if [ "$LIST_TESTS" = true ]; then
  # Only list tests if requested.
  sudo cargo-nextest nextest list "${COMMON_ARGS[@]}"
else
  # Run the tests.
  sudo CPTRA_FIRMWARE_BUNDLE="${HOME}/${DEST_DIR}/all-fw.zip" \
    cargo-nextest nextest run \
      "${COMMON_ARGS[@]}" \
      --test-threads=${RUST_TEST_THREADS} \
      --status-level=all \
      --no-fail-fast \
      --profile=nightly \
      --success-output=immediate \
      "$RUN_SPECIFIC_TEST"
fi
