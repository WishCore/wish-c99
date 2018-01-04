VERSION=`git describe`;
npm i
node node_modules/gulp/bin/gulp.js
TARGET=../build/wish-${VERSION}-source.tar.gz
cp ../build/wish-source.tar.gz $TARGET
