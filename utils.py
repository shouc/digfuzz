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
    print(f"chmod +x {remote_path}")
    ssh_client.exec_command(f"chmod +x {remote_path}")


def setup():
    os.system("gcc -c -g qemu_qsym_harness.c -no-pie -o driver.o")


def compile_harness(obj_loc):
    os.system(f"gcc {obj_loc} driver.o -no-pie -g -o {config.LOCAL_UNINSTRUMENTED_EXEC_PATH}")
