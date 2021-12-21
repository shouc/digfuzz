import time

import instr_interface
import pwn
import config
import os


class STDINExecutorQEMU:
    def __init__(self, qemu_bin, uninstrumented_path, instrumented_path):
        self.instance = None
        self.qemu_bin = qemu_bin
        self.uninstrumented_path = uninstrumented_path
        self.instrumented_path = instrumented_path

    def run_bin(self):
        if self.instance is None:
            self.restart_bin()

    def restart_bin(self):
        self.instance = pwn.process([self.qemu_bin, self.uninstrumented_path])
        assert self.instance.recvline(timeout=30) == b"init\n"

    # todo: qemu tcg instrumentation needs restart everytime because it is JIT, which is bad
    def execute_test_case(self, corpus_content):
        try:
            self.instance.kill()
        except Exception as e:
            pass
        self.instance.restart_bin()
        self.instance.sendline(f"{len(corpus_content) + 1}".encode("ascii"))
        self.instance.sendline(corpus_content)

    # convert output to a list of PCs
    def dump_trace(self):
        out = self.instance.recvall(timeout=config.QEMU_TIMEOUT)
        return map(lambda x: int(x[8:]), filter(lambda x: x.startswith("digfuzz"), out.split("\n")))


class QEMUInstr(instr_interface.Instrumentation):
    def __init__(self, executor, dumper_path, shm_key="/digfuzz"):
        super().__init__(executor)
        self.corpus_traces = {}
        self.dumper_path = dumper_path
        self.shm_key = shm_key
        self.visited_trace = set()
        self.__non_comp_bb = set()
        self.__grab_non_comp_bb()

    # QEMU would dump all BBs, even those call / jmp, we have to know this!
    def __grab_non_comp_bb(self):
        floc = f"/tmp/objdump-log-{time.time()}"
        os.system(f"objdump -d {self.executor.uninstrumented_path} > {floc}")
        record_next = False
        for line in open(floc).read().split("\n"):
            line_arr = line.split("\t")
            if record_next:
                # ['', '', '', '', '1265:\t66', '66', '2e', '0f', '1f', '84', '00', '\tdata16', 'cs', 'nopw', '0x0(%rax,%rax,1)']
                if len(line_arr) > 5:
                    pc = int("0x" + line_arr[5].split(":")[0])
                    self.__non_comp_bb.add(pc)
                record_next = False
            if "\tcall" in line_arr or "\tjmp" in line_arr:
                record_next = True

    def __add_to_execution_tree(self, trace, file_name):
        last_node = None
        for addr in trace:
            if addr not in self.execution_tree:
                self.execution_tree[addr] = instr_interface.Node()
                self.execution_tree[addr].addr = addr
                if addr not in self.__non_comp_bb:
                    self.execution_tree[addr].is_comp = True
            current_node = self.execution_tree[addr]
            if last_node is not None and (last_node.left != current_node and last_node.right != current_node):
                if last_node.left is None:
                    last_node.left = current_node
                elif last_node.right is None:
                    last_node.right = current_node
                else:
                    print("[Exec Tree] More than 2 children for a node :(")
            current_node.led_by = file_name
            last_node = current_node

    def __build_execution_tree(self, new_testcase_filenames):
        for filename in new_testcase_filenames:
            if filename[0] == ".":
                continue
            with open(filename, "rb") as fp:
                corpus_content = fp.read()
                self.executor.execute_test_case(corpus_content)
                try:
                    trace = self.executor.dump_trace()
                except EOFError as e:
                    print(f"[Crash] Found crash {filename} with error {e}, skipping")
                self.corpus_traces[filename] = trace
                self.__add_to_execution_tree(trace, filename)

    def __add_qemu_bb_dumper_out_to_tree(self, content):
        for line in content.split("\n"):
            line_arr = line.split(",")
            pc, counter = line_arr[0], line_arr[1]
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
        return self.execution_tree
