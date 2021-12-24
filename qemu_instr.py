import time

import instr_interface
import pwn
import config
import os

import utils


class STDINExecutorQEMU:
    def __init__(self, qemu_bin, uninstrumented_path):
        self.instance = None
        self.qemu_bin = qemu_bin
        self.uninstrumented_path = uninstrumented_path

    def run_bin(self):
        if self.instance is None:
            self.restart_bin()

    def restart_bin(self):
        self.instance = pwn.process([self.qemu_bin, self.uninstrumented_path])

    def execute_test_case(self, corpus_content):
        self.instance.sendline(corpus_content)

    # convert output to a list of PCs
    def dump_trace(self):
        out = self.instance.recvuntil(b'EXECDONE', timeout=config.QEMU_TIMEOUT)
        return map(lambda x: int(x[8:]), filter(lambda x: x.startswith(b"digfuzz"), out.split(b"\n")))


class QEMUInstr(instr_interface.Instrumentation):
    def __init__(self, executor, dumper_path, shm_key="/digfuzz"):
        super().__init__(executor)
        self.corpus_traces = {}
        self.dumper_path = dumper_path
        self.shm_key = shm_key
        self.visited_trace = set()
        self.__non_comp_bb = set()
        self.__grab_non_comp_bb()
        self.executor.run_bin()

    # QEMU would dump all BBs, even those call / jmp, we have to know this!
    def __grab_non_comp_bb(self):
        floc = f"/tmp/objdump-log-{time.time()}"
        os.system(f"objdump -d {self.executor.uninstrumented_path} > {floc}")
        record_next = False
        driver_part = False
        for line in open(floc).read().split("\n"):
            line_arr = line.split("\t")
            if record_next and len(line_arr) > 2 and ("nop" in line_arr[-1]):
                continue
            if record_next or driver_part:
                if len(line_arr) > 1:
                    pc = int("0x" + line_arr[0].split(":")[0].replace(" ", ""), 16)
                    self.__non_comp_bb.add(pc)
                record_next = False

            # todo: parse instead of direct match
            if len(line_arr) > 2 and ("call" in line_arr[-1] or "jmp" in line_arr[-1]):
                record_next = True
            if len(line_arr) == 1:
                record_next = True
                driver_part = False
            if len(line_arr) == 1 and ("<main>" in line_arr[-1] or "<__libc_csu" in line_arr[-1]):
                driver_part = True

    def __add_to_execution_tree(self, trace, file_name):
        last_node = None
        last_addr = 0
        if file_name not in self.corpus_traces:
            self.corpus_traces[file_name] = []

        for addr in trace:
            if addr not in self.execution_tree:
                self.execution_tree[addr] = instr_interface.Node()
                self.execution_tree[addr].addr = addr
                if addr not in self.__non_comp_bb:
                    self.execution_tree[addr].is_comp = True
                self.execution_tree[addr].addr_range = (0, 1e10)
            # refine addr range
            addr_range = self.execution_tree[addr].addr_range
            if addr_range[1] - addr_range[0] >  addr - last_addr:
                self.execution_tree[addr].addr_range = (last_addr, addr)
            last_addr = addr
            current_node = self.execution_tree[addr]
            if last_node is not None and (last_node.left != current_node and last_node.right != current_node):
                if last_node.left is None:
                    last_node.left = current_node
                elif last_node.right is None:
                    last_node.right = current_node
                else:
                    print("[Exec Tree] More than 2 children for a node :(")
            current_node.led_by = file_name
            self.corpus_traces[file_name].append(current_node)
            last_node = current_node

    def __build_execution_tree(self, new_testcase_filenames):
        for filename in new_testcase_filenames:
            with open(filename, "rb") as fp:
                corpus_content = fp.read()
                self.executor.execute_test_case(corpus_content)
                try:
                    trace = self.executor.dump_trace()
                except EOFError as e:
                    print(f"[Crash] Found crash {filename} with error {e}, skipping")
                    self.executor.restart_bin()
                    continue
                self.__add_to_execution_tree(trace, filename)

    def __add_qemu_bb_dumper_out_to_tree(self, content):
        for line in content.split(b"\n"):
            if not line:
                continue
            line_arr = line.split(b",")
            pc, counter = int(line_arr[0]), int(line_arr[1])
            if pc in self.execution_tree:
                self.execution_tree[pc].visit_count = counter

    def call_dumper(self):
        return pwn.process(self.dumper_path, env={
            "DIGFUZZ_SHM": self.shm_key
        }).recvall(timeout=config.QEMU_TIMEOUT)

    def __increment_tree_visit_count(self):
        content = self.call_dumper()
        self.__add_qemu_bb_dumper_out_to_tree(content)

    def build_execution_tree(self, new_testcase_filenames):
        self.__build_execution_tree(new_testcase_filenames)
        self.__increment_tree_visit_count()
        self.assign_prob()
        return self.execution_tree


if __name__ == "__main__":

    code_loc = "test.c"
    os.system(f"gcc -c {code_loc} -no-pie -o {code_loc}.o")

    utils.setup()
    utils.compile_harness(f"{code_loc}.o")
    uninstrumented_executable = "harness"

    _executor = STDINExecutorQEMU(config.QEMU_BIN, uninstrumented_executable)
    qemu = QEMUInstr(_executor, config.DUMPER_PATH, shm_key=config.SHM_KEY)
    with open("/tmp/qemu1-test", "wb+") as fp:
        fp.write(b"kbcdeffx")
    with open("/tmp/qemu2-test", "wb+") as fp:
        fp.write(b"")
    qemu.build_execution_tree(["/tmp/qemu1-test", "/tmp/qemu2-test"])
    qemu.dump_execution_tree()
