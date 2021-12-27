import multiprocessing
import sys
import os

import config
import utils

if len(sys.argv) > 1 and sys.argv[1].endswith(".o"):
    utils.compile_harness(sys.argv[1])
elif len(sys.argv) > 1:
    os.system(f"cp {sys.argv[1]} ./harness")
else:
    code_loc = "test.c"
    utils.setup()
    os.system(f"gcc -g -c {code_loc} -no-pie -o {code_loc}.o")
    utils.compile_harness(f"{code_loc}.o")

processes = []


def run_async_cmd(cmd):
    print(cmd)
    p = multiprocessing.Process(target=lambda _: os.system(cmd), args=(-1,))
    p.daemon = True
    p.start()
    processes.append(p)


run_async_cmd(f"DIGFUZZ_SHM=/{config.SHM_KEY} "
              f"{config.AFL_FUZZ_PATH} -Q -i {config.AFL_IN_PATH} -o {config.AFL_OUT_PATH} -M {config.AFL_MASTER_NAME} "
              f"-- {config.LOCAL_UNINSTRUMENTED_EXEC_PATH} fuzz")

for i in range(config.AFL_NUM_SLAVE):
    run_async_cmd(
        f"DIGFUZZ_SHM=/{config.SHM_KEY} "
        f"{config.AFL_FUZZ_PATH} -Q -i {config.AFL_IN_PATH} -o {config.AFL_OUT_PATH} -S {config.AFL_SLAVE_NAME}_{i} "
        f"-- {config.LOCAL_UNINSTRUMENTED_EXEC_PATH} fuzz")


for p in processes:
    p.join()
