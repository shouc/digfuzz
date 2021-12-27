import instr_interface
import utils
import pwn
import re
import os


# CONFIGS

# LOCAL: afl-fuzz + tree.py
# REMOTE: qsym
#
# REMOTE and LOCAL should have same copy of code
#
# LOCAL SETUP:
#   mkdir /tmp/digfuzz
#   clang -fsanitize-coverage=bb,trace-pc-guard,indirect-calls,\
#       trace-cmp,no-prune -fsanitize=address -g test.cc FuzzingEngine.a -o test.fuzz
# LOCAL AFL CMD:
#   AFL_SKIP_CPUFREQ=1 ./afl-fuzz -i in/ -o out/ -M f1 ./test.fuzz
#   AFL_SKIP_CPUFREQ=1 ./afl-fuzz -i in/ -o out/ -S f2 ./test.fuzz

# REMOTE SETUP:
# build qsym ...
# build uninstrumented bin:
#   clang -c -g angr_harness.c -o angr_harness.o
#   clang -g angr_harness.o test.cc -o test.angr

class GDBExecutor:
    EXTRACT_START = re.compile(b"starts at address 0x(.+?) ")
    EXTRACT_END = re.compile(b"and ends at 0x(.+?) ")

    def __init__(self, uninstrumented_path):
        self.gdb_instance = None
        self.uninstrumented_path = uninstrumented_path
        self.cmp_table = {}

    def restart_gdb(self):
        self.gdb_instance = pwn.process(["gdb", self.uninstrumented_path])
        self.gdb_instance.recvuntil("(gdb) ")

    def run_gdb(self):
        if self.gdb_instance is None:
            self.restart_gdb()

    def execute_gdb_cmd(self, cmd):
        assert self.gdb_instance
        self.gdb_instance.sendline(cmd)
        return self.gdb_instance.recvuntil("(gdb) ").replace(b"\n", b"")

    def get_addr(self, file_loc):
        if file_loc in self.cmp_table:
            return self.cmp_table[file_loc]
        self.run_gdb()
        real_file_loc = b':'.join(file_loc.split(b':')[:-1])  # todo: fix
        result = self.execute_gdb_cmd(b"info line " + real_file_loc)  # todo: fix
        if b"starts at address" in result and b"and ends at" in result:
            start = self.EXTRACT_START.split(result)
            end = self.EXTRACT_END.split(result)
            assert len(start) == 3 and len(end) == 3, "GDB gives something weird"
            result = [int(b'0x' + start[1], 16), int(b'0x' + end[1], 16)]
        else:
            print(result)
            print(f"[GDB] gdb thinks we give a bad file_loc {real_file_loc}")
            return None
        self.cmp_table[file_loc] = result
        return result


class STDINExecutorLLVM:
    def __init__(self, build_dir, uninstrumented_path, instrumented_path):
        self.instance = None
        self.build_dir = build_dir
        self.uninstrumented_path = uninstrumented_path
        self.instrumented_path = instrumented_path
        self.gdb_instance = None

    def run_bin(self):
        if self.instance is None:
            self.restart_bin()

    def restart_bin(self):
        self.instance = pwn.process([self.instrumented_path, "p"])
        assert self.instance.recvline(timeout=30) == b"init\n"

    def execute_test_case(self, corpus_content):
        self.instance.sendline(f"{len(corpus_content) + 1}".encode("ascii"))
        self.instance.sendline(corpus_content)

    def read_and_determine_done_reading(self):
        assert self.instance
        result = ''
        while len(result) < 7 or result[:7] != b'digfuzz':
            result = self.instance.recvline(timeout=30)
        if result == b'digfuzz_done\n':
            return 0, False
        return result[8:-1], True


class LLVMInstr(instr_interface.Instrumentation):
    def __init__(self, executor, trace_directory="/tmp/digfuzz"):
        super().__init__(executor)
        self.trace_directory = trace_directory
        self.corpus_traces = {}
        self.cmp_table = {}
        self.visited_trace = set()
        self.gdb = GDBExecutor(executor.uninstrumented_path)

    def __add_to_execution_tree(self, trace, file_name):
        last_node = None
        for i in trace:
            addr = i[0]
            is_cmp = i[1]
            file_loc = None
            if is_cmp:
                file_loc = i[2]
            if addr not in self.execution_tree:
                self.execution_tree[addr] = instr_interface.Node()
                self.execution_tree[addr].addr = addr
                self.execution_tree[addr].is_comp = is_cmp
                if file_loc:
                    self.execution_tree[addr].angr_addr_range = self.gdb.get_addr(file_loc)
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
        for i in new_testcase_filenames:
            if i[0] == ".":
                continue
            with open(i, "rb") as fp:
                corpus_content = fp.read()
                self.executor.run_bin()
                self.executor.execute_test_case(corpus_content)
                trace = []
                while 1:
                    try:
                        content, should_continue = self.executor.read_and_determine_done_reading()
                        if not should_continue: break
                        if content[0] == 99:  # b'c'
                            # cmp
                            trace[-1][1] = True
                            trace[-1][2] = content.split(b',')[-1]
                        else:
                            trace.append([int(content, 16), False, b'1'])
                    except EOFError as e:
                        print(f"[Crash] Found crash {i}, skipping")
                        self.executor.restart_bin()
                        break
                self.corpus_traces[i] = trace
                self.__add_to_execution_tree(trace, i)

    def __increment_tree_visit_count(self):
        current_check_trace_files = set(os.listdir(self.trace_directory)).difference(self.visited_trace)
        for i in current_check_trace_files:
            self.visited_trace.add(i)
            with open(f"{self.trace_directory}/{i}") as fp:
                content = fp.readlines()
                for addr in content:
                    if addr == "EOF\n" or "0x" not in addr:
                        continue
                    try:
                        addr = int(addr[:-1], 16)
                    except Exception as e:
                        print(e, addr)
                    if addr not in self.execution_tree:
                        print("[Fuzzer] Fuzzer found a new path but did not add it to corpus")
                        continue
                    self.execution_tree[addr].visit_count += 1

    def build_execution_tree(self, new_testcase_filenames):
        self.__build_execution_tree(new_testcase_filenames)
        self.__increment_tree_visit_count()
        return self.execution_tree
