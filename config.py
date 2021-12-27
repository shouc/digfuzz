import os

import pwn

# Target to fuzz
OBJ_PATH = "test.c.o"

# AFL slave count
AFL_NUM_SLAVE = 1

# NO NEED TO CHANGE
LOCAL_UNINSTRUMENTED_EXEC_PATH = "./harness"
REMOTE_UNINSTRUMENTED_EXEC_PATH = "/tmp/harness"

QEMU_BIN = "./qemu_stdout"

DUMPER_PATH = "./dumper"
SHM_KEY = f"tuba.shm"

QEMU_TIMEOUT = 30
QSYM_TIMEOUT = 30

# NO NEED TO CHANGE IF USING run_afl.py
AFL_FUZZ_PATH = "./AFLplusplus/afl-fuzz"
AFL_IN_PATH = "./in"
AFL_OUT_PATH = "./out"
AFL_SLAVE_NAME = "s"
AFL_MASTER_NAME = "m"
AFL_CORPUS_PATH = f"{AFL_OUT_PATH}/{AFL_MASTER_NAME}/queue"  # the directory of the afl master corpus

# QSYM Remote setup
USE_SSH = False
if not USE_SSH:
    os.system(f"mkdir /tmp/digfuzz && cp {LOCAL_UNINSTRUMENTED_EXEC_PATH} /tmp/digfuzz/harness")
    PIN_SH = "/workdir/qsym/third_party/pin-2.14-71313-gcc.4.4.7-linux/pin.sh"  # the location of qsym script remote
    QSYM_OBJECT_PATH = "/workdir/qsym/qsym/pintool/obj-intel64/libqsym.so"  # the location of qsym pin obj remote
    QSYM_IMAGE_NAME = "qsym"
    QSYM_CMD = ["docker", "-v", "/tmp/digfuzz:/tmp/digfuzz", QSYM_IMAGE_NAME]

else:
    QSYM_HOST = '54.245.74.219'
    QSYM_UN = 'ubuntu'
    QSYM_KEYFILE = "./seem-priv-key.PEM"
    QSYM_SSH_CONN = pwn.ssh(host=QSYM_HOST, user=QSYM_UN, keyfile=QSYM_KEYFILE)
    PIN_SH = "/home/ubuntu/qsym/third_party/pin-2.14-71313-gcc.4.4.7-linux/pin.sh"  # the location of qsym script remote
    QSYM_OBJECT_PATH = "/home/ubuntu/qsym/qsym/pintool/obj-intel64/libqsym.so"  # the location of qsym pin obj remote


