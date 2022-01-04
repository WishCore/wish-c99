cd ..;
VERSION=`git describe`;
if [ -z "$VERSION" ]; then
VERSION=`cat VERSION`
fi
mkdir build;
cd build;
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_ARM64=ON ..;
make;
TARGET=wish-core-${VERSION}-arm64-darwin
cp wish-core $TARGET
strip $TARGET;
cd ../tools
