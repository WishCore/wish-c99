cd ..;
VERSION=`git describe`;
if [ -z "$VERSION" ]; then
VERSION=`cat VERSION`
fi
mkdir build;
cd build;
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_IA32=OFF ..;
make;
cd ../tools
