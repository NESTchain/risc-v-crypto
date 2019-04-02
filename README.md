# risc-v-crypto

Author: μNEST dev team, http://iotee.io

This repo is forked from https://github.com/trezor/trezor-crypto.

Take the following steps to cross-compile it for RISC-V platform. We will take the "secp256k1" part of this crypto library as an example. The cross-compiling platform is Ubuntu 16.04/18.04 x64.

## Install RISC-V GNU toolchain

Install the toolchain to ~/opt/riscv.

```
sudo apt-get install -y autoconf automake autotools-dev curl libmpc-dev libmpfr-dev \
	libgmp-dev libusb-1.0-0-dev gawk build-essential bison flex texinfo gperf libtool \
	patchutils bc zlib1g-dev device-tree-compiler pkg-config libexpat-dev
cd ~ && git clone --recursive https://github.com/riscv/riscv-tools
export RISCV=~/opt/riscv
cd ~/riscv-tools && ./build.sh
```

## Cross-compiling the demo program for RISC-V

```
cd ~ && git clone --recursive https://github.com/NESTchain/risc-v-crypto
export PATH=~/opt/riscv/bin:$PATH
make
```

## Run the secp256k1 demo program in RISC-V emulator

```
spike pk ./demo
```

