cd ..;
VERSION=`git describe`;
if [ -z "$VERSION" ]; then
VERSION=`cat VERSION`
fi
mkdir build;
cd build;
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_IA32=ON ..;
make;
TARGET=wish-core-${VERSION}-ia32-linux
cp wish-core $TARGET
strip $TARGET;
cd ../tools
