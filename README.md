# Quick build instructions

## CMake build

From the `tools` directory run the `debug-x64-linux.sh`. It will build the project to the `build` directory.

For release builds use the `release-x64-linux.sh` and `release-ia32-linux.sh`.

## Release source code

The source release script is based on `gulp` and requires node.js. If node.js is installed:

```sh
cd tools
./release-source-apache2.sh
```

The output goes to the `build` directory. I.e. `../build/wish-v0.8.0-beta-2-source.tar.gz`

## Manual build using CMake

```sh
mkdir build
cd build 
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_IA32=[ON|OFF] ..
make
```
