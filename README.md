# DigFuzz
*Unofficial* Implementation of DigFuzz from paper "Send Hardest Problems My Way: Probabilistic Path Prioritization for Hybrid Fuzzing"



### Setup Executor
Executor is the part of DigFuzz that collects coverage and bb hit count data. Currently, we support QEMU or LLVM. 

**QEMU**:

QEMU is instrumented to dump bb hit count to a shared memory region where DigFuzz can read. 

``` bash
./build_all_qemu.sh
```

**LLVM**:

`trace-pc-guard` feature of LLVM is used to provide bb hit count information. Although this is faster than using QEMU, translating the address of LLVM instrumented binary to that of uninstrumented binary (concolic execution tools have difficulty with instrumented binaries) may not be accurate. 

*TODO*

### Setup Concolic Execution Tools
Concolic execution tool is the part of DigFuzz that conducts directed solving. Fundamentally, it is a function that takes in a binary and a list of code location (representing a path), then provides an input that makes binary go through this path. Currently, we support QSYM or SymCC. 

**QSYM**:  

Given QSYM is built on old version of LLVM, you can use a remote instance with Ubuntu 14.04 and setup QSYM there. 

Run following command at remote host:
``` bash
git clone https://github.com/sslab-gatech/qsym.git && cd qsym
vim qsym.diff # copy content from qsym.diff in this repo to remote
git apply qsym.diff
./setup.sh
pip install .
```

Then, edit the `config.py` to set the credential for accessing that instance and installation location of QSYM. 

**SymCC**:  

*TODO*


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
python3 digfuzz.py
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
