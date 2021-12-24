import os

import paramiko
import config


def copy_file_to_qsym_host(local_path, remote_path):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=config.QSYM_HOST, username=config.QSYM_UN, key_filename=config.QSYM_KEYFILE)
    ftp_client = ssh_client.open_sftp()
    ftp_client.put(local_path, remote_path)
    ftp_client.close()


def qsym_host_provide_permission(remote_path):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=config.QSYM_HOST, username=config.QSYM_UN, key_filename=config.QSYM_KEYFILE)
    ssh_client.exec_command(f"chmod +X {remote_path}")


def setup():
    os.system("gcc -c qsym_harness.c -o qsym_harness.o")
    os.system("gcc -c qemu_aggr_harness.c -o qemu_aggr_harness.o")


def compile_qsym_harness(obj_loc):
    os.system(f"gcc {obj_loc} qsym_harness.o -no-pie -o qsym_harness")

