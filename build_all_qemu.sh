# build AFL++
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make all
cd qemu_mode
./build_qemu_support.sh
cd ../..

# build aggr qemu
cp -R AFLplusplus/qemu_mode ./qemuafl_aggr
cd qemuafl_aggr
git checkout -p ../qemuafl_bb_aggr_shm.diff
cd ..
./build_qemu_with_instr.sh qemuafl_aggr
mv afl-qemu-trace AFLplusplus/

# build qemu stdout
cp -R AFLplusplus/qemu_mode ./qemuafl_stdout
cd qemuafl_stdout
git checkout -p ../qemuafl_bb_stdout.diff
cd ..
./build_qemu_with_instr.sh qemuafl_stdout
mv afl-qemu-trace qemu_stdout

# build qemu dumper
gcc -lrt dump_digfuzz.c -o dumper
