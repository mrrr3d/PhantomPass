# PhantomPass

## Overview

This repository provides both NS2-based simulation and a Tofino1 testbed implementation for PhantomPass.

## NS2 Simulation

The end host implementation is based on [SIRD-Simulator](https://github.com/epfl-dcsl/SIRD-Simulator.git)

### Dependencies

- OS: Linux (tested on **Ubuntu 24.04**)

Install the build tools, NS2 dependencies, and Python packages below.

```bash
sudo apt install build-essential autoconf automake libxmu-dev bc
sudo apt install python3-numpy
sudo apt install python3-matplotlib

sudo apt install python3-pip
pip3 install psutil
```

### Build

Build the ns-2.34 from source.

```bash
git clone https://github.com/mrrr3d/PhantomPass.git
cd phantompass/ns2.34
./install
```

### Run

Load the environment and run an example.

```bash
cd phantompass
source env.sh
cd scripts/r2p2/coord
./run ./config/examples/leaf-spine-ppass-dctcp-w3.sh 1 1 1 1 0 &> out_w3.txt
```

### Results

Find the output artifacts and logs here.

- Simulation outputs are written to `scripts/r2p2/coord/results`.

## Testbed (Tofino)

The testbed P4 code is under `tofino/`.

### Environment

- Intel P4 Studio SDE 9.13.3
