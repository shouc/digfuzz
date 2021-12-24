# build AFL++
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make all
cd qemu_mode
./build_qemu_support.sh
cd ../..

# headers
mkdir afl_shared
cp AFLplusplus/include/*.h afl_shared/

git clone https://github.com/AFLplusplus/qemuafl.git

# build aggr qemu
cp -R qemuafl ./qemuafl_aggr
cd qemuafl_aggr
cp ../qemuafl_bb_aggr_shm.diff .
git apply ./qemuafl_bb_aggr_shm.diff
cd ..
./build_qemu_first.sh qemuafl_aggr
mv afl-qemu-trace AFLplusplus/

# build qemu stdout
cp -R qemuafl ./qemuafl_stdout
cd qemuafl_stdout
cp ../qemuafl_bb_stdout.diff .
git apply ./qemuafl_bb_stdout.diff
cd ..
./build_qemu_first.sh qemuafl_stdout
mv afl-qemu-trace qemu_stdout

# build qemu dumper
gcc dump_digfuzz.c -o dumper -lrt
