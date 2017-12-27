cd ..;
VERSION=`git describe`;
mkdir build;
cd build;
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_IA32=ON ..;
make;
cd ../tools
