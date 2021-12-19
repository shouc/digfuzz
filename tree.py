import os
import random
import time
import pwn
import re
import json
import z3

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

# connect to qsym host
#QSYM_SSH_CONN = pwn.ssh(host='54.245.74.219', user="ubuntu", keyfile="/home/shou/Downloads/shou-ws.pem")
QSYM_SSH_CONN = pwn.ssh(host='54.245.74.219', user="ubuntu", keyfile="/home/shou/coding/digfuzz/seem-priv-key.PEM")

EXECUTION_TRACES_DIR = "/tmp/digfuzz"  # where the traces are dumped, in afl, I set it to /tmp/digfuzz
BUILD_PREFIX = "/home/shou/coding/digfuzz/"  # the directory of the code locally
CORPUS_DIR = "/home/shou/coding/digfuzz/out/f1/queue"  # the directory of the afl master corpus
EXECUTABLE_FUZZER_PATH = "/home/shou/coding/digfuzz/test.fuzz"  # the location of fuzz bin locally
EXECUTABLE_ANGR_PATH_REMOTE = "/home/ubuntu/qsym/tests/syscall/mremap/test.angr"  # the location of uninstrumented bin remote
PIN_SH = "/home/ubuntu/qsym/third_party/pin-2.14-71313-gcc.4.4.7-linux/pin.sh"  # the location of qsym script remote
QSYM_OBJECT_PATH = "/home/ubuntu/qsym/qsym/pintool/obj-intel64/libqsym.so"  # the location of qsym pin obj remote
QSYM_TIMEOUT = 30


# Exec Tree
class Node:
    left = None
    right = None
    addr = 0
    left_prob = -1
    right_prob = -1
    is_comp = False
    visit_count = 1
    angr_addr_range = None
    led_by = ""

    @staticmethod
    def to_addr(node):
        if node:
            return node.addr
        return 0

    def __str__(self):
        return f"left: {self.to_addr(self.left)}; " \
               f"right: {self.to_addr(self.right)}; " \
               f"comp: {self.is_comp}; " \
               f"vc: {self.visit_count}; " \
               f"left_prob: {self.left_prob}; " \
               f"right_prob: {self.right_prob};" \
               f"led_by: {self.led_by}" \
               f"addr_range: {self.angr_addr_range}"


exec_tree_instance = None
gdb_instance = None
execution_tree = {}
cmp_table = {}
corpus_traces = {}
ALREADY_VISITED_CORPUS_FILE = set()
ALREADY_VISITED_TRACE_FILE = set()


# binary runtime
def restart_bin():
    global exec_tree_instance
    exec_tree_instance = pwn.process([EXECUTABLE_FUZZER_PATH, "p"])
    assert exec_tree_instance.recvline(timeout=30) == b"init\n"
    return exec_tree_instance


def run_bin():
    global exec_tree_instance
    if exec_tree_instance is None:
        exec_tree_instance = restart_bin()
    return exec_tree_instance


def restart_gdb():
    global gdb_instance
    gdb_instance = QSYM_SSH_CONN.process(["gdb", EXECUTABLE_ANGR_PATH_REMOTE])
    gdb_instance.recvuntil("(gdb) ")
    return gdb_instance


def run_gdb():
    global gdb_instance
    if gdb_instance is None:
        gdb_instance = restart_gdb()
    return gdb_instance


# extract gdb line2addr result
EXTRACT_START = re.compile(b"starts at address 0x(.+?) ")
EXTRACT_END = re.compile(b"and ends at 0x(.+?) ")


def get_angr_addr(file_loc):
    if file_loc in cmp_table:
        return cmp_table[file_loc]
    gdb = run_gdb()
    real_file_loc = b':'.join(file_loc.split(b':')[:-1])  # todo: fix
    gdb.sendline(b"info line " + real_file_loc.replace(BUILD_PREFIX.encode('ascii'), b""))
    result = gdb.recvuntil("(gdb) ")
    result = result.replace(b"\n", b"")
    if b"starts at address" in result and b"and ends at" in result:
        start = EXTRACT_START.split(result)
        end = EXTRACT_END.split(result)
        assert len(start) == 3 and len(end) == 3, "GDB gives something weird"
        result = [int(b'0x' + start[1], 16), int(b'0x' + end[1], 16)]
    else:
        print(result)
        print(f"[GDB] gdb thinks we give a bad file_loc {real_file_loc}")
        return None
    cmp_table[file_loc] = result
    return result


# stdout utils for our instrumentation
def read_and_determine_done_reading(instance):
    result = ''
    while len(result) < 7 or result[:7] != b'digfuzz':
        result = instance.recvline(timeout=30)
    if result == b'digfuzz_done\n':
        return 0, False
    return result[8:-1], True


# re-exec a corpus file and add it to exec tree
def add_to_execution_tree(trace, file_name):
    last_node = None
    for i in trace:
        addr = i[0]
        is_cmp = i[1]
        file_loc = None
        if is_cmp:
            file_loc = i[2]
        if addr not in execution_tree:
            execution_tree[addr] = Node()
            execution_tree[addr].addr = addr
            execution_tree[addr].is_comp = is_cmp
            if file_loc:
                execution_tree[addr].angr_addr_range = get_angr_addr(file_loc)
        current_node = execution_tree[addr]
        if last_node is not None and (last_node.left != current_node and last_node.right != current_node):
            if last_node.left is None:
                last_node.left = current_node
            elif last_node.right is None:
                last_node.right = current_node
            else:
                print("[Exec Tree] More than 2 children for a node :(")
        current_node.led_by = file_name
        last_node = current_node


def dump_execution_tree():
    print(json.dumps({x: str(execution_tree[x]) for x in execution_tree}, sort_keys=True, indent=4))


# build exec tree with corpus
def build_execution_tree():
    current_check_corpus_files = set(os.listdir(CORPUS_DIR)).difference(ALREADY_VISITED_CORPUS_FILE)
    for i in current_check_corpus_files:
        ALREADY_VISITED_CORPUS_FILE.add(i)
        if i[0] == ".":
            continue
        with open(f"{CORPUS_DIR}/{i}", "rb") as fp:
            corpus_content = fp.read()
            ex_instance = run_bin()
            ex_instance.sendline(f"{len(corpus_content) + 1}".encode("ascii"))
            ex_instance.sendline(corpus_content)
            trace = []
            while 1:
                try:
                    content, should_continue = read_and_determine_done_reading(ex_instance)
                    if not should_continue: break
                    if content[0] == 99:  # b'c'
                        # cmp
                        trace[-1][1] = True
                        trace[-1][2] = content.split(b',')[-1]
                    else:
                        trace.append([int(content, 16), False, b'1'])
                except EOFError as e:
                    print(f"[Crash] Found crash {CORPUS_DIR}/{i}, skipping")
                    restart_bin()
                    break
            corpus_traces[i] = trace
            add_to_execution_tree(trace, i)


# update visit count for each node in exec tree
def increment_tree_visit_count():
    current_check_trace_files = set(os.listdir(EXECUTION_TRACES_DIR)).difference(ALREADY_VISITED_TRACE_FILE)
    for i in current_check_trace_files:
        ALREADY_VISITED_TRACE_FILE.add(i)
        with open(f"{EXECUTION_TRACES_DIR}/{i}") as fp:
            content = fp.readlines()
            for addr in content:
                if addr == "EOF\n" or "0x" not in addr:
                    continue
                try:
                    addr = int(addr[:-1], 16)
                except Exception as e:
                    print(e, addr)
                if addr not in execution_tree:
                    print("[Fuzzer] Fuzzer found a new path but did not add it to corpus")
                    continue
                execution_tree[addr].visit_count += 1


def dfs_helper(current_node_addr, visited_nodes):
    if current_node_addr in visited_nodes:
        return
    visited_nodes.add(current_node_addr)
    current_node = execution_tree[current_node_addr]

    left_node = execution_tree[current_node_addr].left
    right_node = execution_tree[current_node_addr].right
    should_assign_prob = current_node.is_comp
    sum_of_children = 1  # prevent div by 0, todo: this causes left + right != 1

    if left_node is not None:
        dfs_helper(left_node.addr, visited_nodes)
        sum_of_children += left_node.visit_count

    if right_node is not None:
        dfs_helper(right_node.addr, visited_nodes)
        sum_of_children += right_node.visit_count

    if left_node is not None:
        current_node.left_prob = left_node.visit_count / sum_of_children
    else:
        current_node.left_prob = 3 / sum_of_children

    if right_node is not None:
        current_node.right_prob = right_node.visit_count / sum_of_children
    else:
        current_node.right_prob = 3 / sum_of_children

    if not should_assign_prob or sum_of_children < 30:
        current_node.left_prob = 1
        current_node.right_prob = 1


def assign_prob():
    dfs_helper(next(iter(execution_tree)), set())


def get_prob(parent, child):
    parent_node = execution_tree[parent]
    child_node = execution_tree[child]
    if parent_node.left and parent_node.left == child_node:
        return parent_node.left_prob
    if parent_node.right and parent_node.right == child_node:
        return parent_node.right_prob
    print(f"[Exec] {parent} {child} not in execution tree")
    assert False


def is_branch_missed(parent):
    parent_node = execution_tree[parent]
    return parent_node.right is None and parent_node.is_comp


def get_top_20_missed_path():
    missed_paths = []
    for filename in corpus_traces:
        t = corpus_traces[filename]
        prob = 1
        for k, addr in enumerate(t):
            if k == len(t) - 1:
                # we are done
                break
            addr = addr[0]
            next_addr = t[k + 1][0]
            if is_branch_missed(addr):
                missed_path = t[:k + 2]
                missed_path_prob = prob * execution_tree[addr].right_prob
                missed_paths.append([missed_path, missed_path_prob, filename])
            prob *= get_prob(addr, next_addr)
    return sorted(missed_paths, key=lambda x: x[1])


def parse_qsym_output(lines):
    lines = lines.split(b"\n")
    concating_constraint = False
    current_pc = -1
    current_constraint = b''
    constraints = []
    bvs = set()
    for i in lines:
        if len(i) > 1 and i[:2] == b'SB':
            current_pc = int(i[2:], 16)
        if b'(declare-fun' in i:
            bvs.add(i)
        if b'(assert' in i:
            concating_constraint = True
        if b'(check-sat)' in i:
            constraints.append([current_pc, current_constraint])
            current_constraint = b''
            concating_constraint = False
            continue
        if not concating_constraint:
            continue
        current_constraint += i
    return bvs, constraints


def run_qsym_remote(corpus_path):
    QSYM_SSH_CONN.process(["mkdir", "in"])
    QSYM_SSH_CONN.process(["mkdir", "out"])
    with open(corpus_path, "rb") as fp:
        corpus_content = fp.read()
        qsym_instance = QSYM_SSH_CONN.process([PIN_SH, '-ifeellucky', '-t',
                                               QSYM_OBJECT_PATH, '-i', 'in', '-o', 'out', '--',
                                               EXECUTABLE_ANGR_PATH_REMOTE, str(len(corpus_content) + 1)])
        print(corpus_content)
        qsym_instance.sendline(corpus_content)
    result = qsym_instance.recvall(timeout=QSYM_TIMEOUT)
    return result


def qsym_helper(trace, constraints):
    start_from_pc = 0
    to_be_solved = []
    print(trace, constraints)
    for node in [execution_tree[x[0]] for x in trace]:
        to_solve_constraint = None
        if node.angr_addr_range is None:
            continue
        for offset, constraint in enumerate(constraints[start_from_pc:]):
            pc = constraint[0]
            constraint_content = constraint[1]
            if node.angr_addr_range[0] <= pc <= node.angr_addr_range[1]:
                start_from_pc += offset + 1
                to_solve_constraint = constraint_content
                break
        if to_solve_constraint is None:
            print(f"QSYM: {str(node)} branch is constant")
        else:
            to_be_solved.append(to_solve_constraint)
    return to_be_solved


def remove_assert(string):
    cter = -1
    met_assert = False
    while 1:
        cter += 1
        if met_assert and string[cter] == 40:
            string = string[cter:]
            break
        if string[cter] == 40:  # b'('
            met_assert = True
            continue
    cter = len(string)
    while 1:
        cter -= 1
        if string[cter] == 41:  # b')'
            string = string[:cter]
            break
    return string


def negate_smt2(string):
    string = remove_assert(string)
    return f'(assert (not {string.decode("utf-8")}))'.encode('utf-8')


def to_smt2(bvs, constraints):
    smt2 = b''
    for bv in bvs:
        smt2 += bv + b'\n'
    for constraint in constraints:
        smt2 += constraint + b'\n'
    return smt2.decode('utf-8')


def solve_smt(smt):
    s = z3.Solver()
    s.from_string(smt)
    try:
        s.check()

        m = s.model()
        result = []
        for d in m.decls():
            result.append([d.name(), m[d]])
        result = sorted(result, key=lambda x: x[0])
        return bytes([int(x[1].__str__()) for x in result])
    except Exception as e:
        print(f"[Solver] UNSAT {e}")


def do_concolic_execution(path):
    concrete_file = path[2]
    result = run_qsym_remote(CORPUS_DIR + '/' + concrete_file)
    bvs, constraints = parse_qsym_output(result)
    to_be_solved = qsym_helper(path[0], constraints)
    if len(to_be_solved) == 0:
        print("[Solver] Conc exec gives nothing")
        return
    to_be_solved[-1] = negate_smt2(to_be_solved[-1])
    return solve_smt(to_smt2(bvs, to_be_solved))


added_counter = int(1e6)


# not tested, but seems to work...
def add_input_to_afl_queue(content):
    if not content:
        return
    global added_counter
    with open("%s/id:%6d,src:digfuzz" % (CORPUS_DIR, added_counter), "wb+") as fp:
        fp.write(content)
    added_counter += 1


while 1:
    build_execution_tree()
    increment_tree_visit_count()
    assign_prob()
    dump_execution_tree()
    missed = get_top_20_missed_path()
    solving_missed = random.choice(missed)
    print(f"Solving for path {solving_missed[0]} with prob {solving_missed[1]}")
    if len(solving_missed[0]) > 0:
        add_input_to_afl_queue(do_concolic_execution(solving_missed))
    time.sleep(5)  # allow fuzzer to sync corpus
    print("Round done")

