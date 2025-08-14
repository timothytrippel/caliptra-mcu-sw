# Overview

This subdir provides tools for building, deploying, and running CaliptraSS tests on the Versal FPGA board.

# Prerequsites

To use this tool flow, we assume you have the following pre-configured.

### Hardware and SSH Setup
1. a Versal FPGA board setup with ssh access,
2. an SSH configuration file with `mcu-host` as the hostname for the FPGA board, and
3. docker installed.

### Docker Image Build

We use a Docker container to perform cross-compilations of FPGA (Rust) test harness since the FPGA board is running Ubuntu22.04 and may have different system dependency (e.g., glibc) versions than your host workstation.

To install the Docker image run:
```sh
docker pull ghcr.io/chipsalliance/caliptra-build-image:latest
```

# Test Build and Deployment Flow

The CaliptraSS FPGA tests can be cross-compiled for the FPGA board and copied to the board by running the following:

1. Cross-compile FPGA tests for FPGA's ARM core and copy them to the FPGA board:
`./util/fpga/build-and-deploy-tests-to-fpga.sh`

2. SSH to FPGA board: `ssh mcu-host`

3. Navigate to user destination dir that files were copied to: `cd ${HOME}/<dst>`

4. Run the FPGA tests.
   a. Unpack (`-u` option) and run all tests:
   `./run-fpga-tests.sh -d <dst dir in ${HOME}/> -u`
   b. Run a specific test (`-t` option), skipping unpack operation:
   `./run-fpga-tests.sh -d <dst dir in ${HOME}/> -t model_fpga_realtime::test::test_new_unbooted`
   c. List all available tests (`-l` option):
   `./run-fpga-tests.sh -d <dst dir in ${HOME}/> -l`
