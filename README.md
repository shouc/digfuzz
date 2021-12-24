# DigFuzz
*Unofficial* Implementation of DigFuzz from paper "Send Hardest Problems My Way: Probabilistic Path Prioritization for Hybrid Fuzzing"

### Setup (QEMU + QSYM)
``` bash
./build_all_qemu.sh
```

### Start Fuzzing (QEMU + QSYM)
Compile your target with `LLVMFuzzerTestOneInput` exported and `-no-pie ` enabled, which should yield a .o file
```bash
CFLAGS="-no-pie" CXXFLAGS="-no-pie" make fuzzer
```
Edit `config.py` for path of the .o file
```bash
vim config.py
```

If not configured system for AFL, do
```bash
sudo ./AFLplusplus/afl-system-config
```

In one terminal (AFL stuffs)
```bash
python3 run_afl.py
```
In another terminal (QSYM stuffs)
```bash
python3 main.py
```


### QEMU-based Instrumentation Workflow
QEMU side:
1. Dump BB hitcount to shared memory 

Our side:
1. Re-execute corpus inputs to build execution tree. (Not concolic execution, just concrete execution with instrumentation)
2. Read shared memory and add BB visit count to execution tree
3. Do a DFS on execution to assign probabilities for each edge
4. Identify missed branch in all corpus traces and build a priority queue for these traces with priority as 1-probability
5. QSYM do concolic execution on the missed branch to identify input
6. Add input to AFL corpus


### LLVM-based Instrumentation Workflow
AFL side:
1. Compile binary with two harness, one for AFL, another for angr. 
2. Instrument AFL binary via Clang to provide block information. 

Our side:
1. Re-execute corpus inputs to build execution tree. (Not concolic execution, just concrete execution with instrumentation)
2. For every trace AFL binary gives, add visit count to the execution tree.
3. Do a DFS on execution to assign probabilities for each edge
4. Identify missed branch in all corpus traces and build a priority queue for these traces with priority as 1-probability
5. QSYM do concolic execution on the missed branch to identify input
6. Add input to AFL corpus
