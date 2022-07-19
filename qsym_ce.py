import re
import time

import config
import z3


# hacky smt parsing
def remove_assert(string):
    cter = -1
    met_assert = False
    while 1:
        cter += 1
        if met_assert and string[cter] == 40:
            string = string[cter:]
            break
        if string[cter] == 40 and string[cter + 1:cter + 7] == b'assert':  # b'('
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


def get_bv_value(smt):
    match_res = re.compile(r"(k![0-9]+) \(\)").findall(smt)
    if len(match_res) < 1:
        assert False, "Can't find declare-fun"
    return sorted(list(set([int(x.replace("k!", "")) for x in match_res])))


def solve_smt(smt, orig):
    if type(orig) == bytes:
        orig = [x for x in orig]
    else:
        orig = [ord(x) for x in orig]
    s = z3.Solver()
    s.set("timeout", config.QSYM_TIMEOUT)
    s.from_string(smt)
    bvs = get_bv_value(smt)
    try:
        s.check()
        m = s.model()
        result = []
        known = set()
        for d in m.decls():
            known.add(d.name())
            result.append((int(d.name().replace('k!', "")), m[d]))
        for idx, sol in result:
            idx = bvs.index(idx)
            if idx >= len(orig):
                print(smt)
                print(idx, len(orig))
                orig.append(int(sol.__str__()))
                continue
            orig[idx] = int(sol.__str__())
        return bytes(orig)
    except Exception as e:
        print(f"[Solver] UNSAT {e}")


def to_smt2(bvs, constraints):
    smt2 = b''
    for bv in bvs:
        smt2 += bv + b'\n'
    smt2 += constraints + b'\n'
    return smt2.decode('utf-8')


class QSYMConcolicExecutor:
    def __init__(self, uninstrumented_executable):
        self.uninstrumented_executable = uninstrumented_executable
        self.cmp_constraint = {}
        self.execution_tree = None
        self.qsym_instance = None
        self.__run_qsym()
        self.__cache = {}

    def __set_cache(self, testcase_fn, bvs, cmp_constraints):
        self.__cache[testcase_fn] = (bvs, cmp_constraints)

    def __get_cache(self, testcase_fn, handler, *args):
        if testcase_fn in self.__cache:
            return self.__cache[testcase_fn]
        return handler(*args)

    def update_exec_tree(self, tree):
        self.execution_tree = tree

    def __run_qsym(self):
        if config.USE_SSH:
            config.QSYM_SSH_CONN.process(["mkdir", "in"])
            config.QSYM_SSH_CONN.process(["mkdir", "out"])
            self.qsym_instance = config.QSYM_SSH_CONN.process([config.PIN_SH, '-ifeellucky', '-t',
                                                               config.QSYM_OBJECT_PATH, '-i', 'in', '-o', 'out', '--',
                                                               self.uninstrumented_executable])
        else:
            self.qsym_instance = config.QSYM_SSH_CONN.process(config.QSYM_CMD + [config.PIN_SH, '-ifeellucky', '-t',
                                                                                 config.QSYM_OBJECT_PATH, '-i',
                                                                                 '/tmp/in', '-o',
                                                                                 '/tmp/out', '--',
                                                                                 uninstrumented_executable])
        self.qsym_instance.recvuntil(b"[INFO] IMG: /lib/x86_64-linux-gnu/libc.so.6")
        print("[QSYM] Ready")

    def __get_result(self, corpus_content):
        try:
            # todo: dont restart qsym
            self.qsym_instance.kill()
            self.__run_qsym()
            #

            self.qsym_instance.sendline(corpus_content)
            start_time = time.time()
            result = self.qsym_instance.recvuntil("EXECDONE", timeout=config.QSYM_TIMEOUT)
            end_time = time.time()
            print(f"[QSYM] Spent {end_time - start_time}s dumping constraints")
        except EOFError as e:
            print(f"[QSYM] Crashed, ignoring content {corpus_content}")
            self.__run_qsym()
            return b''
        return result

    @staticmethod
    def __parse_output_flipme(lines: [bytes]):
        recording = False
        current_pc = -1
        current_constraint = []
        cmp_constraint = {}
        bvs = set()
        for i in lines:
            if len(i) > 8 and i[:9] == b'FLIPMEEND':
                recording = False
                continue
            if recording:
                if b'(declare-fun' in i:
                    bvs.add(i)
                    continue
                if b'(check-sat)' in i:
                    cmp_constraint[current_pc] = b'\n'.join(current_constraint)
                    current_constraint = []
                    continue
                current_constraint.append(i)
            if len(i) > 5 and i[:6] == b'FLIPME':
                current_pc = int(i[6:])
                recording = True
        return bvs, cmp_constraint

    def __parse_output(self, lines: bytes):
        lines = lines.split(b"\n")
        # bvs, path_constraints = self.__parse_output_path(lines)
        bvs, cmp_constraint = self.__parse_output_flipme(lines)
        return bvs, cmp_constraint

    # get a list of [cmp constraints] that has pc in pc_wanted_range
    @staticmethod
    def __find_last_cmp_pc(cmp_constraints: dict, pc_wanted_range, nth=0):
        result = []
        for pc in cmp_constraints:
            if pc_wanted_range[0] < pc < pc_wanted_range[1]:
                if nth == 0:
                    result.append(pc)
                nth -= 1
        return result

    # find a path node to stop => find a cmp cons => flip cmp cons & concat
    def __get_constraint(self, flip_pc_range, bvs, cmp_constraints, nth=0):
        cmp_cons_pcs = self.__find_last_cmp_pc(cmp_constraints, flip_pc_range, nth=nth)
        if len(cmp_cons_pcs) == 0:
            print("[QSYM] Trying to flip constant branch")
        for pc in cmp_cons_pcs:
            path = b"\n".join([cmp_constraints[_pc] for _pc in cmp_constraints if _pc < pc])
            yield to_smt2(bvs, path + b'\n' + negate_smt2(cmp_constraints[pc]))

    # conduct concolic execution and flip constraints in flip_pc_range while preserving others
    def flip_it(self, testcase_content, flip_pc_range, nth=0, qemu_instr_obj=None, testcase_fn=""):
        if qemu_instr_obj and testcase_fn:
            qemu_instr_obj.add_solved_path(testcase_fn, flip_pc_range, nth=nth)
        if testcase_fn not in self.__cache:
            result = self.__get_result(testcase_content)
            bvs, cmp_constraint = self.__parse_output(result)
            self.__set_cache(testcase_fn, bvs, cmp_constraint)
        else:
            bvs, cmp_constraint = self.__cache[testcase_fn]
        has_solution = False

        for to_be_solved in self.__get_constraint(flip_pc_range, bvs, cmp_constraint, nth=nth):
            if len(to_be_solved) == 0:
                print("[Solver] Conc exec gives nothing")
                continue
            solution = solve_smt(to_be_solved, testcase_content)
            if not solution:
                continue
            print(f"[QSYM] SAT")
            has_solution = True
            yield solution
        if not has_solution and qemu_instr_obj and testcase_fn:
            qemu_instr_obj.add_unsolvable_path(testcase_fn, flip_pc_range, nth=nth)


if __name__ == "__main__":
    # import os
    import utils
    #
    # code_loc = "test.c"
    # os.system(f"gcc -c {code_loc} -no-pie -o {code_loc}.o")
    #
    # utils.setup()
    # utils.compile_harness(f"{code_loc}.o")
    #
    uninstrumented_executable = "/tmp/qsym_harness"

    utils.copy_file_to_qsym_host("harness", uninstrumented_executable)
    utils.qsym_host_provide_permission(uninstrumented_executable)

    qsym = QSYMConcolicExecutor(uninstrumented_executable)
    for sol in qsym.flip_it(open('./out/m/queue/id:100004,src:100001', "rb").read(), (4247400, 4247489), nth=0):
        print(sol)
