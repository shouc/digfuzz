import time

import instr_interface
import pwn
import config
import os
import angr
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
        driver_part = False
        for line in open(floc).read().split("\n"):
            line_arr = line.split("\t")
            if (len(line_arr) > 2 and ("call" in line_arr[-1] or
                                       "jmp" in line_arr[-1] or
                                       "leave" in line_arr[-1] or
                                       "ret" in line_arr[-1]))\
                    or driver_part:
                if len(line_arr) > 1:
                    pc = int("0x" + line_arr[0].split(":")[0].replace(" ", ""), 16)
                    self.__non_comp_bb.add(pc)
            # todo: parse instead of direct match
            if len(line_arr) == 1:
                driver_part = False
            if len(line_arr) == 1 and ("<main>" in line_arr[-1]
                                       or "<__libc_csu" in line_arr[-1]
                                       or "@plt>" in line_arr[-1]):
                pc = int("0x" + line_arr[0].split(" ")[0].replace(" ", ""), 16)
                self.__non_comp_bb.add(pc)
                driver_part = True

    def __add_to_execution_tree(self, trace, file_name):
        last_addr = 0
        if file_name not in self.corpus_traces:
            self.corpus_traces[file_name] = []
        hit_counts = {}
        trace = list(trace)
        for addr in trace:
            edge = (last_addr, addr)
            hit_counts[edge] = hit_counts[edge] + 1 if edge in hit_counts else 1

            # init node
            if addr not in self.execution_tree:
                self.execution_tree[addr] = instr_interface.Node()
                self.execution_tree[addr].addr = addr
                self.execution_tree[addr].addr_range = (addr, addr + self.basic_block[addr])
                addresses = range(addr, addr + self.basic_block[addr])
                if self.__non_comp_bb.isdisjoint(addresses):
                    self.execution_tree[addr].is_comp = True

            # update children
            current_node = self.execution_tree[addr]
            if last_addr != 0 and addr not in self.execution_tree[last_addr].children:
                self.execution_tree[last_addr].children.add(addr)
            current_node.led_by = file_name
            self.corpus_traces[file_name].append(current_node)
            last_addr = addr

        # setup edge hitcount
        last_addr = None
        for addr in trace:
            if not last_addr:
                last_addr = addr
                continue
            edge = (last_addr, addr)
            hit_count = hit_counts[edge]
            last_node = self.execution_tree[last_addr]
            if addr in last_node.max_encounter_child:
                last_node.max_encounter_child[addr].add(hit_count)
            else:
                last_node.max_encounter_child[addr] = {hit_count}
            last_addr = addr

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
    #
    # code_loc = "test.c"
    # os.system(f"gcc -c {code_loc} -no-pie -o {code_loc}.o")
    #
    # utils.setup()
    # utils.compile_harness(f"{code_loc}.o")
    uninstrumented_executable = "harness"

    _executor = STDINExecutorQEMU(config.QEMU_BIN, uninstrumented_executable)
    qemu = QEMUInstr(_executor, config.DUMPER_PATH, shm_key=config.SHM_KEY)
    with open("/tmp/qemu1-test", "wb+") as fp:
        fp.write(b"kbcdeffx")
    with open("/tmp/qemu2-test", "wb+") as fp:
        fp.write(b"")

    def get_new_testcase_filenames():
        result = []
        for i in os.listdir(config.AFL_CORPUS_PATH):
            if i.startswith("."):
                continue
            result.append(f"{config.AFL_CORPUS_PATH}/{i}")
        return result
    qemu.build_execution_tree(get_new_testcase_filenames())
    qemu.dump_execution_tree()
