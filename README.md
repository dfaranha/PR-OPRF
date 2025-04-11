# PR-OPRF

## Clarification

This repo includes all instructions to re-produce the results in the paper https://eprint.iacr.org/2024/1955.pdf, which is published at IEEE S&P 2025.

## Requirements

* `C++20`
* `gmp`: `brew install gmp` or `sudo apt install libgmp-dev`
* `libtool`: `brew install libtool` or `sudo apt install libtool`
* [libOTe](https://github.com/osu-crypto/libOTe)
* [emp-tool](https://github.com/emp-toolkit/emp-tool)
* [emp-ot](https://github.com/emp-toolkit/emp-ot)

Note: It is possible to install those packages locally to avoid collisions. The way to do it is the following, e.g., for `emp-tool` (e.g., to install in folder `emp-install`):
```
mkdir emp-install
git clone https://github.com/emp-toolkit/emp-tool
mkdir emp-tool/cmake-build
cd emp-tool/cmake-build
cmake -DCMAKE_INSTALL_PREFIX=../../emp-install ..
make install
```
Then, do not forget to set `CMAKE_PREFIX_PATH=/path/to/emp-install`.

Note: For PQ-OT in libOTe, Ubuntu is needed.

Note: We offer a one-shot script located at `setup/setup.sh` to install all necessary dependencies on a freshly installed Ubuntu.
```
cd setup && sudo bash setup.sh && cd ..
```

## Compilation

```
mkdir build && cd build && cmake ../ && make && cd ..
```

## Expected Executables

All executables are located in `build/bin`, including:

* `test_oprf_test_halfmalicious_oprf`: the executable for batched half-malicious 2PC-Gold
* `test_oprf_test_malicious_oprf`: the executable for batched malicious 2PC-Gold
* `test_oprf_test_single_halfmalicious_oprf`: the executable for non-batched half-malicious 2PC-Gold
* `test_oprf_test_single_malicious_oprf`: the executable for non-batched malicious 2PC-Gold
* `test_oprf_test_optimization_para`: the executable for testing optimization parameter phi in non-batched malicious 2PC-Gold

## Usage

Except for the executable to test optimization parameter, the server executes
```
exe 1 PORT IP
```
whereas the client executes
```
exe 2 PORT IP
```

For the executable to test optimization parameter phi, the server executes
```
exe 1 PORT IP phi
```
whereas the client can executes
```
exe 2 PORT IP phi
```

## Example

The server executes
```
test_oprf_test_single_malicious_oprf 1 12345 127.0.0.1
```
whereas the client executes
```
test_oprf_test_single_malicious_oprf 2 12345 127.0.0.1
```

## Macro

We list several MACROs that are needed to enable different experiments:

* `ENABLE_PQ`: set to `true` to enable PQ instantiation
* `ENABLE_FINEGRAIN`: set to `true` to enable fine-grained analysis
* `ENABLE_SMALLN`: set to `true` to enable smaller n experiments in the batched setting