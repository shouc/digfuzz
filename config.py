import pwn

REMOTE_LOAD_ADDRESS = 0x400000

QEMU_TIMEOUT = 30
QSYM_TIMEOUT = 30

QSYM_HOST = '54.245.74.219'
QSYM_UN = 'ubuntu'
QSYM_KEYFILE = "/home/shou/coding/digfuzz/seem-priv-key.PEM"


QSYM_SSH_CONN = pwn.ssh(host=QSYM_HOST, user=QSYM_UN, keyfile=QSYM_KEYFILE)

PIN_SH = "/home/ubuntu/qsym/third_party/pin-2.14-71313-gcc.4.4.7-linux/pin.sh"  # the location of qsym script remote
QSYM_OBJECT_PATH = "/home/ubuntu/qsym/qsym/pintool/obj-intel64/libqsym.so"  # the location of qsym pin obj remote

