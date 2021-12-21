import pwn

QEMU_TIMEOUT = 30
QSYM_TIMEOUT = 30
QSYM_SSH_CONN = pwn.ssh(host='54.245.74.219', user="ubuntu", keyfile="/home/shou/coding/digfuzz/seem-priv-key.PEM")
PIN_SH = "/home/ubuntu/qsym/third_party/pin-2.14-71313-gcc.4.4.7-linux/pin.sh"  # the location of qsym script remote
QSYM_OBJECT_PATH = "/home/ubuntu/qsym/qsym/pintool/obj-intel64/libqsym.so"  # the location of qsym pin obj remote


