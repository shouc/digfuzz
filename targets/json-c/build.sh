git clone --depth 1 https://github.com/json-c/json-c.git target
cd target
mkdir json-c-build
cd json-c-build
cmake -DBUILD_SHARED_LIBS=OFF ..
CFLAGS=-no-pie CXXFLAGS=-no-pie make -j$(nproc)
cd ..
g++ -std=c++11 -no-pie -I. -I./json-c-build fuzz/tokener_parse_ex_fuzzer.cc ./json-c-build/libjson-c.a ../../../driver.o -o harness -lbsd
cp harness ..
cd ..