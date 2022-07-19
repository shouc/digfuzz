import os
import random
import sys
import time

import config
import qemu_instr
import qsym_ce
import utils
import pwn

# pwn.log.setLevel("silent")


# not tested, but seems to work...
def add_input_to_afl_queue(content, idx="000000"):
    if not content:
        return
    global added_counter
    with open("%s/id:%6d,src:%s" % (config.AFL_CORPUS_PATH, added_counter, idx), "wb+") as fp:
        fp.write(content)
    added_counter += 1


added_counter = int(1e5)
utils.copy_file_to_qsym_host(config.LOCAL_UNINSTRUMENTED_EXEC_PATH, config.REMOTE_UNINSTRUMENTED_EXEC_PATH)
utils.qsym_host_provide_permission(config.REMOTE_UNINSTRUMENTED_EXEC_PATH)

_executor = qemu_instr.STDINExecutorQEMU(config.QEMU_BIN, config.LOCAL_UNINSTRUMENTED_EXEC_PATH)
qemu = qemu_instr.QEMUInstr(_executor, config.DUMPER_PATH, shm_key=config.SHM_KEY)
qsym = qsym_ce.QSYMConcolicExecutor(config.REMOTE_UNINSTRUMENTED_EXEC_PATH)

known_testcase = set()


def get_new_testcase_filenames():
    result = []
    for i in os.listdir(config.AFL_CORPUS_PATH):
        if i in known_testcase or i.startswith("."):
            continue
        known_testcase.add(i)
        result.append(f"{config.AFL_CORPUS_PATH}/{i}")
    return result


def grab_id_from_afl_tc_name(name):
    return name.split("id:")[1].split(",")[0]


while 1:
    qemu.build_execution_tree(get_new_testcase_filenames())
    # qemu.dump_execution_tree()
    paths = qemu.get_sorted_missed_path()
    if len(paths) == 0:
        print("Let's wait for AFL")
        time.sleep(5)
        continue
    solving_path = random.choice(paths)
    print(f"Solving for path {solving_path} with prob {solving_path['prob']}")
    testcase_content = open(solving_path["fn"], "rb").read()
    for solution in qsym.flip_it(testcase_content, solving_path["flip"],
                                 nth=solving_path["nth"],
                                 qemu_instr_obj=qemu,
                                 testcase_fn=solving_path["fn"]):
        add_input_to_afl_queue(solution, idx=grab_id_from_afl_tc_name(solving_path["fn"]))
    print("Round done")
