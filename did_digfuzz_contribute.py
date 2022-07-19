import os
import config
import qemu_instr

_executor = qemu_instr.STDINExecutorQEMU(config.QEMU_BIN, config.LOCAL_UNINSTRUMENTED_EXEC_PATH)
qemu = qemu_instr.QEMUInstr(_executor, config.DUMPER_PATH, shm_key=config.SHM_KEY)
tests = list(filter(lambda x: "10000" not in x and not x.startswith("."), os.listdir("out/m/queue")))
qemu.build_execution_tree(["out/m/queue/" + x for x in tests])

tests = list(filter(lambda x: "10000" in x and not x.startswith("."), os.listdir("out/m/queue")))

for filename in ["out/m/queue/" + x for x in tests]:
    with open(filename, "rb") as fp:
        corpus_content = fp.read()
        qemu.executor.execute_test_case(corpus_content)
        try:
            trace = qemu.executor.dump_trace()
        except EOFError as e:
            print(f"[Crash] Found crash {filename} with error {e}, skipping")
            qemu.executor.restart_bin()
            continue
        for i in trace:
            if i not in qemu.execution_tree:
                print(i, filename)
