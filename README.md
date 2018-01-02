# Quick build instructions

## CMake build

From the `tools` directory run the `debug-x64-linux.sh`. It will build the project to the `build` directory.

For release builds use the `release-x64-linux.sh` and `release-ia32-linux.sh`.

## Manual build using CMake

```sh
mkdir build
cd build 
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_IA32=[ON|OFF] ..
make
```
