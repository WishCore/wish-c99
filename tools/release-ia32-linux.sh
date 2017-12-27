cd ..;
VERSION=`git describe`;
mkdir build;
cd build;
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_IA32=ON ..;
make;
strip wish-core;
cd ../tools
