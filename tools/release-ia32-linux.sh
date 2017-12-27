cd ..;
VERSION=`git describe`;
mkdir build;
cd build;
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_IA32=ON ..;
make;
TARGET=wish-core-${VERSION}-ia32-linux
cp wish-core $TARGET
strip $TARGET;
cd ../tools
