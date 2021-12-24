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
        if string[cter] == 40 and string[cter+1:cter+7] == b'assert':  # b'('
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
    print("="*30)
    print(string)
    print("="*30)
    string = remove_assert(string)
    return f'(assert (not {string.decode("utf-8")}))'.encode('utf-8')


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
        self.__run_qsym_remote()

    def update_exec_tree(self, tree):
        self.execution_tree = tree

    def __run_qsym_remote(self):
        config.QSYM_SSH_CONN.process(["mkdir", "in"])
        config.QSYM_SSH_CONN.process(["mkdir", "out"])
        self.qsym_instance = config.QSYM_SSH_CONN.process([config.PIN_SH, '-ifeellucky', '-t',
                                                           config.QSYM_OBJECT_PATH, '-i', 'in', '-o', 'out', '--',
                                                           self.uninstrumented_executable])
        self.qsym_instance.recvuntil(b"[INFO] IMG: /lib/x86_64-linux-gnu/libc.so.6")
        print("[QSYM] Ready")

    def __get_result(self, corpus_content):
        self.qsym_instance.sendline(corpus_content)
        start_time = time.time()
        result = self.qsym_instance.recvuntil("EXECDONE", timeout=config.QSYM_TIMEOUT)
        end_time = time.time()
        print(f"[QSYM] Spent {end_time - start_time}s dumping constraints")
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
    def __find_last_cmp_pc(cmp_constraints: dict, pc_wanted_range):
        result = []
        for pc in cmp_constraints:
            if pc_wanted_range[0] < pc < pc_wanted_range[1]:
                result.append(pc)
        return result

    # find a path node to stop => find a cmp cons => flip cmp cons & concat
    def __get_constraint(self, flip_pc_range, bvs, cmp_constraints):
        cmp_cons_pcs = self.__find_last_cmp_pc(cmp_constraints, flip_pc_range)
        for pc in cmp_cons_pcs:
            path = b"\n".join([cmp_constraints[_pc] for _pc in cmp_constraints if _pc < pc])
            yield to_smt2(bvs, path + b'\n' + negate_smt2(cmp_constraints[pc]))

    # conduct concolic execution and flip constraints in flip_pc_range while preserving others
    def flip_it(self, testcase_content, flip_pc_range, qemu_instr_obj=None, testcase_fn=None):
        result = self.__get_result(testcase_content)
        print(result)
        bvs, cmp_constraint = self.__parse_output(result)
        has_solution = False

        for to_be_solved in self.__get_constraint(flip_pc_range, bvs, cmp_constraint):
            if len(to_be_solved) == 0:
                print("[Solver] Conc exec gives nothing")
                continue
            print(to_be_solved)
            solution = solve_smt(to_be_solved)
            if not solution:
                continue
            print(f"[QSYM] SAT: {to_be_solved}")
            has_solution = True
            yield solution
        if not has_solution and qemu_instr_obj and testcase_fn:
            qemu_instr_obj.add_unsolvable_path(testcase_fn, flip_pc_range)


if __name__ == "__main__":
    import os
    import utils

    code_loc = "test.c"
    os.system(f"gcc -c {code_loc} -no-pie -o {code_loc}.o")

    utils.setup()
    utils.compile_harness(f"{code_loc}.o")

    uninstrumented_executable = "/tmp/qsym_harness"

    utils.copy_file_to_qsym_host("harness", uninstrumented_executable)
    utils.qsym_host_provide_permission(uninstrumented_executable)

    qsym = QSYMConcolicExecutor(uninstrumented_executable)
    print(qsym.flip_it(b"abcdeffx", [0x40000 + x for x in [0x12b7, 0x12be]]))
