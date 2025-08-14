#!/bin/bash

REPO_TOP="$(git rev-parse --show-toplevel)"

# Cross compile the tests for the FPGA environment.
docker run --rm -t \
  -v $HOME/.cargo/registry/cache:/root/.cargo/registry/cache \
  -v $HOME/.cargo/registry/git:/root/.cargo/registry/git  \
  -v "${PWD}":/work-dir \
  -w /work-dir \
  caliptra-fpga:latest \
  /bin/bash \
  -c ". util/fpga/cross-compiling/build-fpga-tests.sh"

# Copy the tests to the FPGA board.
rsync -avzP \
  target/all-fw.zip \
  target/aarch64-unknown-linux-gnu/debug/xtask \
  caliptra-test-bins.tar.zst \
  "${REPO_TOP}/util/fpga/run-fpga-tests.sh" \
  mcu-host:"$USER"
