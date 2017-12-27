cd ..;
VERSION=`git describe`;
mkdir build;
cd build;
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_IA32=OFF ..;
make;
TARGET=wish-core-${VERSION}-linux
cp wish-core $TARGET
strip $TARGET;
cd ../tools
