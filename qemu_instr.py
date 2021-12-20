import instr_interface
import pwn
import config

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
    def __init__(self, executor):
        super().__init__(executor)
        self.corpus_traces = {}
        self.visited_trace = set()

    def __add_to_execution_tree(self, trace, file_name):
        last_node = None
        for addr in trace:
            if addr not in self.execution_tree:
                self.execution_tree[addr] = instr_interface.Node()
                self.execution_tree[addr].addr = addr
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
            if i[0] == ".":
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

    def __increment_tree_visit_count(self):
        current_check_trace_files = set(self.corpus_traces.keys()).difference(self.visited_trace)
        for filename in current_check_trace_files:
            for addr in self.corpus_traces[filename]:
                if addr not in self.execution_tree:
                    print("[Fuzzer] Fuzzer found a new path but did not add it to corpus")
                    continue
                self.execution_tree[addr].visit_count += 1

    def build_execution_tree(self, new_testcase_filenames):
        self.__build_execution_tree(new_testcase_filenames)
        self.__increment_tree_visit_count()
        return self.execution_tree
