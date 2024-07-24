# PR-OPRF

## Requirements

* `gmp`: `brew install gmp`
* [emp-tool](https://github.com/emp-toolkit/emp-tool) -> TODO specify commit used in case of compatibility issues
* [emp-ot](https://github.com/emp-toolkit/emp-ot) -> TODO specify commit used in case of compatibility issues

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